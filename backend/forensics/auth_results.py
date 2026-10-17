"""Legacy authentication helpers. The public evaluate_authentication entry point
returns unverified header claims without DNS. Historical explicit live helpers
are retained for reference and are not used by the local application."""

import re
import ipaddress
from typing import Optional, Dict, List

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


DNS_TIMEOUT_SECONDS = 4


# ============================================================
# TIER 1 — Parse verdicts the receiving mail server already stamped
# ============================================================

def parse_authentication_results(all_headers: dict) -> Dict[str, Optional[str]]:
    """
    Parses the "Authentication-Results" header, which looks like:
        Authentication-Results: mx.google.com;
            spf=pass (google.com: domain of x@y.com designates 1.2.3.4 as permitted sender)
            dkim=fail header.i=@y.com
            dmarc=pass header.from=y.com

    Returns {"spf": "pass"/"fail"/None, "dkim": ..., "dmarc": ...}
    None means this header didn't mention that check at all.
    """
    result = {"spf": None, "dkim": None, "dmarc": None}

    auth_headers = all_headers.get("Authentication-Results", [])
    combined_text = " ".join(auth_headers)

    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", combined_text, re.IGNORECASE)
        if match:
            result[mechanism] = match.group(1).lower()

    return result


def parse_received_spf_header(all_headers: dict) -> Optional[str]:
    """
    Older/alternate style: some mail servers use a dedicated "Received-SPF"
    header instead of folding it into Authentication-Results, e.g.:
        Received-SPF: pass (domain of x@y.com designates 1.2.3.4 as permitted sender)
    """
    headers = all_headers.get("Received-SPF", [])
    if not headers:
        return None
    match = re.match(r"^\s*(\w+)", headers[0])
    return match.group(1).lower() if match else None


# ============================================================
# TIER 2 — Live DNS fallback checks
# ============================================================

def _query_txt_records(domain: str) -> List[str]:
    """Fetch all TXT records for a domain. Returns [] on any failure
    (domain doesn't exist, no network, timeout, etc.) rather than raising."""
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT_SECONDS
        resolver.lifetime = DNS_TIMEOUT_SECONDS
        answers = resolver.resolve(domain, "TXT")
        return ["".join(part.decode("utf-8", errors="replace") for part in rdata.strings) for rdata in answers]
    except Exception:
        return []


def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False


def _resolve_a_records(domain: str) -> List[str]:
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT_SECONDS
        resolver.lifetime = DNS_TIMEOUT_SECONDS
        answers = resolver.resolve(domain, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


def evaluate_spf_live(sender_domain: str, originating_ip: Optional[str], _depth: int = 0) -> Dict:
    """
    Real (simplified) SPF evaluation via live DNS lookup. Supports:
    ip4, ip6, a, mx, include (one level of recursion only — matches most
    real-world SPF setups), and the trailing all/~all/-all/+all qualifier.
    """
    if not sender_domain or not originating_ip:
        return {"verdict": "none", "record_found": False, "explanation": "missing domain or IP"}

    if _depth > 1:
        return {"verdict": "permerror", "record_found": False, "explanation": "include recursion depth exceeded"}

    txt_records = _query_txt_records(sender_domain)
    spf_record = next((r for r in txt_records if r.strip().lower().startswith("v=spf1")), None)

    if not spf_record:
        return {"verdict": "none", "record_found": False, "explanation": f"no SPF record found for {sender_domain}"}

    mechanisms = spf_record.split()[1:]
    final_qualifier = "?all"

    for mech in mechanisms:
        qualifier = "+"
        if mech and mech[0] in "+-~?":
            qualifier, mech = mech[0], mech[1:]

        if mech == "all":
            final_qualifier = qualifier + "all"
            break

        elif mech.startswith("ip4:") or mech.startswith("ip6:"):
            cidr = mech.split(":", 1)[1]
            if _ip_in_cidr(originating_ip, cidr):
                return {"verdict": "pass" if qualifier in ("+", "") else _qualifier_to_verdict(qualifier),
                        "record_found": True, "explanation": f"matched {mech}"}

        elif mech == "a" or mech.startswith("a:") or mech.startswith("a/"):
            target_domain = mech.split(":")[1] if ":" in mech else sender_domain
            for ip in _resolve_a_records(target_domain.split("/")[0]):
                if ip == originating_ip:
                    return {"verdict": "pass" if qualifier in ("+", "") else _qualifier_to_verdict(qualifier),
                            "record_found": True, "explanation": f"matched a:{target_domain}"}

        elif mech.startswith("include:"):
            included_domain = mech.split(":", 1)[1]
            sub_result = evaluate_spf_live(included_domain, originating_ip, _depth=_depth + 1)
            if sub_result["verdict"] == "pass":
                return {"verdict": "pass", "record_found": True, "explanation": f"matched via include:{included_domain}"}

    verdict = _qualifier_to_verdict(final_qualifier[0]) if final_qualifier != "?all" else "neutral"
    return {"verdict": verdict, "record_found": True, "explanation": f"fell through to '{final_qualifier}'"}


def _qualifier_to_verdict(qualifier: str) -> str:
    return {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}.get(qualifier, "neutral")


def extract_dkim_signature_info(all_headers: dict) -> Optional[Dict[str, str]]:
    """Extracts the signing domain (d=) and selector (s=) from a
    DKIM-Signature header, if present — needed to check the public key."""
    dkim_headers = all_headers.get("DKIM-Signature", [])
    if not dkim_headers:
        return None

    header_text = dkim_headers[0]
    d_match = re.search(r"[;\s]d=([^;]+)", header_text)
    s_match = re.search(r"[;\s]s=([^;]+)", header_text)

    if not d_match or not s_match:
        return None

    return {
        "domain": d_match.group(1).strip(),
        "selector": s_match.group(1).strip(),
    }


def evaluate_dkim_live(all_headers: dict, from_domain: Optional[str]) -> Dict:
    """
    Best-effort DKIM check (NOT full cryptographic verification — see
    module docstring). Checks whether a DKIM-Signature exists, whether
    the signing domain publishes a real key, and whether it's aligned
    with the From: domain.
    """
    sig_info = extract_dkim_signature_info(all_headers)

    if not sig_info:
        return {"verdict": "no_signature", "key_found": False, "aligned": False,
                "explanation": "no DKIM-Signature header present"}

    key_domain = f"{sig_info['selector']}._domainkey.{sig_info['domain']}"
    txt_records = _query_txt_records(key_domain)
    key_found = any("v=dkim1" in r.lower() or "p=" in r.lower() for r in txt_records) if txt_records else False

    aligned = bool(from_domain) and sig_info["domain"].lower().endswith(from_domain.lower())

    if not key_found:
        verdict = "key_not_found"
        explanation = f"no DKIM public key found at {key_domain} — signature cannot be trusted"
    elif not aligned:
        verdict = "misaligned"
        explanation = f"signing domain ({sig_info['domain']}) does not match From: domain ({from_domain})"
    else:
        verdict = "key_found_unverified"
        explanation = "public key exists and domain is aligned, but signature was not cryptographically verified"

    return {
        "verdict": verdict,
        "key_found": key_found,
        "aligned": aligned,
        "signing_domain": sig_info["domain"],
        "selector": sig_info["selector"],
        "explanation": explanation,
    }


def evaluate_dmarc_live(domain: Optional[str]) -> Dict:
    """Fetches and parses the domain's real DMARC policy record."""
    if not domain:
        return {"verdict": "no_domain", "policy": None, "record_found": False}

    txt_records = _query_txt_records(f"_dmarc.{domain}")
    dmarc_record = next((r for r in txt_records if r.strip().lower().startswith("v=dmarc1")), None)

    if not dmarc_record:
        return {"verdict": "no_record", "policy": None, "record_found": False,
                "explanation": f"no DMARC record at _dmarc.{domain} — domain has no DMARC policy"}

    policy_match = re.search(r"[;\s]p=(\w+)", dmarc_record)
    policy = policy_match.group(1).lower() if policy_match else "none"

    return {
        "verdict": "record_found",
        "policy": policy,
        "record_found": True,
        "raw_record": dmarc_record,
    }


# ============================================================
# ORCHESTRATION — combines Tier 1 (header) + Tier 2 (DNS fallback)
# ============================================================

def evaluate_authentication(all_headers: dict, from_domain: Optional[str], originating_ip: Optional[str]) -> Dict:
    """No implicit DNS calls or trust in imported Authentication-Results headers."""
    claimed = parse_authentication_results(all_headers)
    return {name: {"verdict": "unknown", "source": "unverified_header_claim",
                   "claimed_result": claimed[name],
                   "details": {"explanation": "No independently validated receiving boundary. DNS was not queried."}}
            for name in ("spf", "dkim", "dmarc")}
