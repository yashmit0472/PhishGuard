# Deterministic scoring, version 2026.10.17.1

The backend owns the scale. Frontend and extension never derive a verdict from a score.
Higher scores mean more warning evidence, not a probability of fraud. For each group,
only its strongest contribution counts, then the sum is capped at 100. Explanations
reference observed evidence IDs; no generative model fills in missing facts.

| Rule ID | Weight | Group |
|---|---:|---|
| credential_request | 35 | persuasion |
| remote_access | 35 | persuasion |
| pressure | 15 | pressure |
| advance_payment | 40 | payment |
| reply_mismatch | 15 | identity |
| sender_disguise | 30 | identity |
| link_disguise | 35 | link |
| executable | 35 | file |
| disguised_file | 70 | file |
| type_mismatch | 70 | file |
| file_type_mismatch | 25 | file |
| macro_behavior | 60 | file |
| reputation | 80 | reputation |
| classifier | 15 | classifier |
| auth_failure | 25 | authentication |

70–100 Dangerous; 30–69 Suspicious; 0–29 Inconclusive when checks are unavailable/failed,
otherwise No red flags found. Input failure yields Analysis unavailable with null score.
Threat evidence can yield Dangerous/Suspicious even when coverage is partial.

Trusted authentication requires an independently validated header boundary supplied by
an internal integration; it cannot be asserted by the public JSON API. Current raw Gmail
and EML flows leave headers unverified. Auth successes never subtract risk. Received
addresses are relay claims, not the sender's device or evidence of VPN bypass.

The local classifier is capped at 15 points and cannot produce a threat verdict alone,
skip a check, or turn an incomplete analysis into proof of legitimacy. Its numeric output
is uncalibrated model output, distinct from overall risk and check coverage.

These rules are heuristics, not a validated production detector. They can misread quoted
warnings, unusual legitimate requests, international domain names, and novel scams.
Hindi/Hinglish templates exist, but detection quality is not established by the small
demo fixture set. No country, Tor, VPN, hosting provider, phone number or UPI ID is
automatically treated as malicious by itself.
