# Gmail setup (account-owner steps)

The local app requires no API key. Gmail requires a public Chrome-extension OAuth
client ID. Never paste passwords, access tokens, client secrets or pairing codes into
chat, source control or logs. An API key cannot replace OAuth mailbox consent.

1. Create a project in https://console.cloud.google.com/ and enable **Gmail API**.
2. Under **Google Auth Platform**, set app name/contact details. For a demo choose
   External / Testing and add each demo account as a test user.
3. Add `https://www.googleapis.com/auth/gmail.readonly` under Data Access.
   This is mailbox-wide read permission, not permission limited to the open email.
4. In Chrome open `chrome://extensions`, enable Developer mode, select **Load unpacked**,
   and select this repository's `extension` folder. Copy its 32-letter extension ID.
5. Create an OAuth client of type **Chrome Extension**, using that ID as Item ID.
   Share the public client ID and extension ID with the developer. No secret is needed.
6. Run `scripts/configure-gmail.ps1 -ClientId YOUR_PUBLIC_CLIENT_ID` or edit the manifest's
   `oauth2.client_id`. Reload the extension. Use the same folder to preserve its local ID.
7. Launch PhishGuard, unlock the app, open extension settings, enter the local pairing
   code, then choose **Connect Gmail**. Use the same account that is open in Gmail.
8. Open a test email. The extension checks only an exact identifiable open message.
   Automatic checking defaults on after setup. Settings explain the data read and allow
   it to be disabled. A manual button is present on each identifiable message.
9. **Sign out** removes Chrome's cached tokens and attempts Google token revocation.
   If offline revocation fails, remove the PhishGuard grant from Google Account connections.
   Disconnect local pairing separately from the app's settings.

## Exact-message limitation

MIME content comes exclusively from documented Gmail API `messages.get?format=raw`.
No "Show original" scraping, InboxSDK, DOM-body reconstruction or mailbox scanning is used.
Gmail has no documented public API for the selected message in its web UI. The locator
therefore uses Gmail's `data-legacy-message-id` and an account label as a fail-closed
adapter. This DOM adapter is not a stable Google contract and needs live testing.
IDs, returned API IDs and cached analysis IDs must agree; account mismatches are rejected.
Each message in a thread has its own panel; navigation invalidates pending results.
If identifiers/account labels are unavailable, use the app's EML upload. Do not claim
universal Gmail compatibility until the configured extension has been tested live.

## Distribution

For a stable distributed extension ID, follow Chrome's public-key/Developer Dashboard
instructions. Public distribution with Gmail restricted scopes can require Google's
verification and, depending on handling, additional assessment. Testing mode is for
approved test accounts and can require renewed authorization. No production approval
is implied by this demo setup.

Official references checked 2026-10-17:
- https://developer.chrome.com/docs/extensions/how-to/integrate/oauth
- https://developer.chrome.com/docs/extensions/reference/api/identity
- https://developers.google.com/workspace/gmail/api/auth/scopes
- https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get
