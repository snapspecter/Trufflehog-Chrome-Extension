# Updated Trufflehog Chrome Extension

A professional-grade credential sniffing and secret detection tool for your browser. This extension monitors web pages, network traffic, and storage for leaked API keys, tokens, and sensitive credentials in real-time.

## Key Features

- **Manifest V3 Compliant:** Built on the latest Chrome extension architecture for security and performance.
- **Multi-Layer Scanning:**
    - **DOM & Shadow DOM:** Recursively scans the visible page and hidden web components.
    - **Network Analysis:** Monitors XHR/Fetch request headers for tokens (e.g., Bearer, Basic Auth).
    - **Browser Storage:** Scans `localStorage`, `sessionStorage`, and `cookies`.
    - **Source Maps:** Automatically detects and scans unminified source maps for hardcoded secrets.
- **Advanced Detection Engine:**
    - **Regex Matching:** 30+ modern patterns for GitHub, AWS, Slack, Stripe, and more.
    - **Entropy Scanning:** Identifies high-randomness strings that may be undiscovered secrets.
    - **Recursive Decoding:** Automatically decodes Base64 strings to find nested secrets.
- **Enterprise Reporting:**
    - **Centralized Webhooks:** Send findings to a Slack webhook or a custom security endpoint.
    - **CSV Export:** Download all findings across all origins for offline analysis.
    - **Desktop Notifications:** Real-time alerts when a secret is detected.
- **Developer Friendly:**
    - **Context Snippets:** View 100 characters of surrounding code for every finding.
    - **Ignore List:** Globally ignore known false positives.
    - **Origin Deny List:** Skip scanning on specific trusted or sensitive domains.

## Installation (Developer Mode)

1. Clone this repository.
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** in the top right.
4. Click **Load unpacked** and select the extension directory.

## Usage

1. Click the **Trufflehog** icon in your toolbar to open the control panel.
2. Toggle the desired scanning modules (Entropy scanning is recommended for deep bug bounty hunting).
3. Browse the web as usual.
4. When the badge icon shows a number, click it to review findings for the current site.
5. (Optional) Configure a **Reporting Webhook** in the settings to centralize your discoveries.

---

##  Verification & Testing

### GitHub Tokens
Test the validity of a GitHub token with:
`curl -H "Authorization: token <TOKEN>" https://api.github.com/user`

### JWT (JSON Web Tokens)
Decode them at [jwt.io](https://jwt.io/) to check for sensitive claims. If the algorithm is `HS256`, you can attempt to crack the secret using Hashcat (mode `16500`).

---

#### Forked from trufflesecurity/Trufflehog-Chrome-Extension

