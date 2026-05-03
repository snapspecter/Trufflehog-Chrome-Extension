// background.js - Phase 2 & 3: Advanced Detection & Context capture

const specifics = {
    "Slack Token": "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|\"][0-9a-f]{32}['|\"]",
    "GitHub Personal Access Token": "ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth Access Token": "gho_[a-zA-Z0-9]{36}",
    "GitHub App Token": "ghs_[a-zA-Z0-9]{36}",
    "GitHub Refresh Token": "ghr_[a-zA-Z0-9]{36}",
    "GitHub Fine-Grained Token": "github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Google Cloud API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Json Web Token": "eyJhbGciOiJ[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Telegram Bot API Key": "[0-9]+:AA[0-9a-z\\-_]{33}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Github Auth Creds": "https:\/\/[a-zA-Z0-9]{40}@github\.com",
    "DigitalOcean Access Token": "dop_v1_[a-f0-9]{64}",
    "NPM Access Token": "npm_[a-zA-Z0-9]{36}",
    "PyPI API Token": "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\\-_]{50,1000}",
    "SendGrid API Key": "SG\\.[a-zA-Z0-9\\-_]{22}\\.[a-zA-Z0-9\\-_]{43}",
    "Firebase API Key": "AIza[0-9A-Za-z\\-_]{35}"
};

const generics = {
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Bearer Token": "[bB][eE][aA][rR][eE][rR]\\s+[a-zA-Z0-9\\-\\._~\\+\\/]+",
};

const aws = {
    "AWS Access Key ID": "AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": "(?i)aws_secret_access_key.{0,20}['|\"]([0-9a-zA-Z\\/\\+]{40})['|\"]",
};

const denyList = ["AIDAAAAAAAAAAAAAAAAA"];

// Shannon Entropy Calculation
function shannonEntropy(str) {
    if (!str) return 0;
    let entropy = 0;
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
        const char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    for (const char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.sync.get(['ranOnce'], (result) => {
        if (!result.ranOnce) {
            chrome.storage.sync.set({ 
                "ranOnce": true,
                "originDenyList": ["https://www.google.com"],
                "globalIgnoreList": []
            });
        }
    });
});

const checkData = async (data, src, regexes, fromEncoded = false, parentUrl = undefined, parentOrigin = undefined) => {
    let findings = [];
    const storage = await chrome.storage.sync.get(["globalIgnoreList", "leakedKeys", "entropy"]);
    const ignoreList = storage.globalIgnoreList || [];
    
    // 1. Regex Scanning
    for (let key in regexes) {
        try {
            let pattern = regexes[key];
            let flags = 'g';
            if (pattern.startsWith("(?i)")) {
                pattern = pattern.substring(4);
                flags = 'gi';
            }
            
            let re = new RegExp(pattern, flags);
            let match;
            while ((match = re.exec(data)) !== null) {
                let matchStr = match[1] || match[0];
                if (denyList.includes(matchStr) || ignoreList.includes(matchStr)) continue;

                // Capture Context
                const start = Math.max(0, match.index - 50);
                const end = Math.min(data.length, match.index + match[0].length + 50);
                const context = data.substring(start, end);

                findings.push({
                    src: src,
                    match: matchStr,
                    key: key,
                    context: context,
                    encoded: fromEncoded,
                    parentUrl: parentUrl,
                    parentOrigin: parentOrigin,
                    timestamp: Date.now()
                });
            }
        } catch (e) {}
    }

    // 2. Entropy Scanning (Phase 2)
    if (storage.entropy) {
        // Simple heuristic: look for long strings of alpha-numeric chars
        const words = data.match(/[a-zA-Z0-9+/=]{20,}/g) || [];
        for (let word of words) {
            if (shannonEntropy(word) > 4.5) { // Threshold for high randomness
                if (denyList.includes(word) || ignoreList.includes(word)) continue;
                
                // Avoid matching common things like base64 blobs by checking if it's already in regex findings
                if (findings.some(f => f.match === word)) continue;

                const index = data.indexOf(word);
                const context = data.substring(Math.max(0, index - 50), Math.min(data.length, index + word.length + 50));

                findings.push({
                    src: src,
                    match: word,
                    key: "High Entropy String",
                    context: context,
                    encoded: fromEncoded,
                    parentUrl: parentUrl,
                    parentOrigin: parentOrigin,
                    timestamp: Date.now()
                });
            }
        }
    }

    if (findings.length > 0) {
        let keys = storage.leakedKeys || {};
        for (let finding of findings) {
            if (!keys[parentOrigin]) keys[parentOrigin] = [];
            
            let isNew = !keys[parentOrigin].some(k => k.match === finding.match && k.key === finding.key);
            if (isNew) {
                keys[parentOrigin].push(finding);
                await chrome.storage.sync.set({ "leakedKeys": keys });
                updateTabAndAlert(finding);
            }
        }
    }

    // 3. Recursive Decoding
    let decodedStrings = getDecodedb64(data);
    for (let encoded of decodedStrings) {
        if (encoded[1] !== data && encoded[1].length > 10) {
            checkData(encoded[1], src + " (decoded)", regexes, encoded[0], parentUrl, parentOrigin);
        }
    }
};

const updateTabAndAlert = (finding) => {
    const { key, match } = finding;
    chrome.storage.sync.get(["alerts"], (result) => {
        if (result.alerts !== false) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon48.png',
                title: 'Secret Found!',
                message: `${key} detected. Check findings in popup.`,
                priority: 2
            });
        }
    });
    updateTab();
};

const updateTab = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length === 0 || !tabs[0].url) return;
        try {
            const url = new URL(tabs[0].url);
            if (!url.protocol.startsWith('http')) {
                chrome.action.setBadgeText({ text: '' });
                return;
            }
            const origin = url.origin;
            chrome.storage.sync.get(["leakedKeys"], (result) => {
                const leakedKeys = result.leakedKeys || {};
                const count = (leakedKeys[origin] || []).length;
                chrome.action.setBadgeText({ text: count > 0 ? count.toString() : "" });
                chrome.action.setBadgeBackgroundColor({ color: '#E53935' });
            });
        } catch (e) {}
    });
};

chrome.tabs.onActivated.addListener(updateTab);
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'complete') updateTab();
});

const getStringsOfSet = (word, char_set, threshold = 20) => {
    let count = 0, letters = "", strings = [];
    if (!word) return [];
    for (let char of word) {
        if (char_set.indexOf(char) > -1) {
            letters += char;
            count += 1;
        } else {
            if (count > threshold) strings.push(letters);
            letters = ""; count = 0;
        }
    }
    if (count > threshold) strings.push(letters);
    return strings;
};

const getDecodedb64 = (inputString) => {
    let b64CharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let encodeds = getStringsOfSet(inputString, b64CharSet);
    let decodeds = [];
    for (let encoded of encodeds) {
        try {
            let decoded = atob(encoded);
            if (/[^ -~]/.test(decoded)) continue; // Skip if contains non-printable chars
            decodeds.push([encoded, decoded]);
        } catch (e) {}
    }
    return decodeds;
};

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    chrome.storage.sync.get(['generics', 'specifics', 'aws', 'checkEnv', 'checkGit'], (settings) => {
        let regexes = {};
        if (settings.generics !== false) regexes = { ...regexes, ...generics };
        if (settings.specifics !== false) regexes = { ...regexes, ...specifics };
        if (settings.aws !== false) regexes = { ...regexes, ...aws };

        if (request.scriptUrl) {
            fetch(request.scriptUrl, { "credentials": 'include' })
                .then(r => r.text())
                .then(data => checkData(data, request.scriptUrl, regexes, undefined, request.parentUrl, request.parentOrigin))
                .catch(() => {});
        } else if (request.pageBody) {
            checkData(request.pageBody, request.origin, regexes, undefined, request.parentUrl, request.parentOrigin);
        } else if (request.envFile && settings.checkEnv) {
            fetch(request.envFile, { "credentials": 'include' })
                .then(r => r.text())
                .then(data => {
                    if (data.includes("=") || data.includes("APP_")) {
                        checkData(data, ".env file", regexes, undefined, request.parentUrl, request.parentOrigin);
                    }
                }).catch(() => {});
        } else if (request.openTabs) {
            request.openTabs.forEach(url => chrome.tabs.create({ url }));
        } else if (request.gitDir && settings.checkGit) {
            fetch(request.gitDir, { "credentials": 'include' })
                .then(r => r.text())
                .then(data => {
                    if (data.includes("[core]")) {
                        chrome.notifications.create({
                            type: 'basic',
                            iconUrl: 'icon48.png',
                            title: 'Git Config Found',
                            message: `Found at ${request.gitDir}`,
                            priority: 1
                        });
                    }
                }).catch(() => {});
        }
    });
    return true;
});
