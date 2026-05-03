// background.js for Manifest V3 - Updated with more modern regexes

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
    "AWS Session Token": "(?i)aws_session_token.{0,20}['|\"]([0-9a-zA-Z\\/\\+]{300,})['|\"]",
};

const denyList = ["AIDAAAAAAAAAAAAAAAAA"];

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.sync.get(['ranOnce'], (result) => {
        if (!result.ranOnce) {
            chrome.storage.sync.set({ "ranOnce": true });
            chrome.storage.sync.set({ "originDenyList": ["https://www.google.com"] });
        }
    });
});

const checkData = async (data, src, regexes, fromEncoded = false, parentUrl = undefined, parentOrigin = undefined) => {
    let findings = [];
    for (let key in regexes) {
        try {
            let pattern = regexes[key];
            // Handle (?i) case-insensitive flag if present (basic support)
            let flags = 'g';
            if (pattern.startsWith("(?i)")) {
                pattern = pattern.substring(4);
                flags = 'gi';
            }
            
            let re = new RegExp(pattern, flags);
            let match;
            while ((match = re.exec(data)) !== null) {
                let matchStr = match[1] || match[0]; // Prefer capture group 1 if it exists
                if (denyList.includes(matchStr)) continue;

                findings.push({
                    src: src,
                    match: matchStr,
                    key: key,
                    encoded: fromEncoded,
                    parentUrl: parentUrl,
                    parentOrigin: parentOrigin
                });
            }
        } catch (e) {
            console.error(`Invalid regex for ${key}: ${regexes[key]}`, e);
        }
    }

    if (findings.length > 0) {
        const result = await chrome.storage.sync.get(["leakedKeys"]);
        let keys = result.leakedKeys || {};

        for (let finding of findings) {
            if (!keys[parentOrigin]) {
                keys[parentOrigin] = [];
            }

            let isNew = !keys[parentOrigin].some(k =>
                k.src === finding.src &&
                k.match === finding.match &&
                k.key === finding.key &&
                k.encoded === finding.encoded &&
                k.parentUrl === finding.parentUrl
            );

            if (isNew) {
                keys[parentOrigin].push(finding);
                await chrome.storage.sync.set({ "leakedKeys": keys });
                updateTabAndAlert(finding);
            }
        }
    }

    let decodedStrings = getDecodedb64(data);
    for (let encoded of decodedStrings) {
        // Avoid infinite recursion by checking if decoded is different from input
        if (encoded[1] !== data) {
            checkData(encoded[1], src, regexes, encoded[0], parentUrl, parentOrigin);
        }
    }
};

const updateTabAndAlert = (finding) => {
    const { key, src, match, encoded } = finding;
    chrome.storage.sync.get(["alerts"], (result) => {
        if (result.alerts === undefined || result.alerts) {
            let message = encoded
                ? `${key}: ${match} found in ${src} decoded from ${encoded.substring(0, 9)}...`
                : `${key}: ${match} found in ${src}`;

            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon48.png',
                title: 'Secret Found!',
                message: message.substring(0, 128), // Limit message length
                priority: 2
            });
        }
    });
    updateTab();
};

const updateTab = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length === 0) return;
        const tab = tabs[0];
        if (!tab.url) return;

        try {
            const url = new URL(tab.url);
            if (url.protocol.startsWith('http')) {
                const origin = url.origin;
                chrome.storage.sync.get(["leakedKeys"], (result) => {
                    const leakedKeys = result.leakedKeys || {};
                    const originKeysCount = (leakedKeys[origin] && leakedKeys[origin].length > 0)
                        ? leakedKeys[origin].length.toString()
                        : "";

                    chrome.action.setBadgeText({ text: originKeysCount });
                    chrome.action.setBadgeBackgroundColor({ color: '#ff0000' });
                });
            } else {
                chrome.action.setBadgeText({ text: '' });
            }
        } catch (e) {
            chrome.action.setBadgeText({ text: '' });
        }
    });
};

chrome.tabs.onActivated.addListener(updateTab);
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete') {
        updateTab();
    }
});

const getStringsOfSet = (word, char_set, threshold = 20) => {
    let count = 0;
    let letters = "";
    let strings = [];
    if (!word) return [];

    for (let char of word) {
        if (char_set.indexOf(char) > -1) {
            letters += char;
            count += 1;
        } else {
            if (count > threshold) {
                strings.push(letters);
            }
            letters = "";
            count = 0;
        }
    }
    if (count > threshold) {
        strings.push(letters);
    }
    return strings;
};

const getDecodedb64 = (inputString) => {
    let b64CharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let encodeds = getStringsOfSet(inputString, b64CharSet);
    let decodeds = [];
    for (let encoded of encodeds) {
        try {
            let decoded = [encoded, atob(encoded)];
            // Only add if it seems like useful text or potential secret
            if (decoded[1].length > 5) {
                decodeds.push(decoded);
            }
        } catch (e) {}
    }
    return decodeds;
};

const checkIfOriginDenied = (check_url, cb) => {
    chrome.storage.sync.get(["originDenyList"], (result) => {
        let originDenyList = result.originDenyList || [];
        let skip = originDenyList.some(origin => check_url.startsWith(origin));
        cb(skip);
    });
};

const checkForGitDir = (data, url) => {
    if (data.includes("[core]") || data.includes("[remote")) {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon48.png',
            title: 'Sensitive Directory Found',
            message: `.git config found at ${url}`,
            priority: 1
        });
    }
};

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    chrome.storage.sync.get(['generics', 'specifics', 'aws', 'checkEnv', 'checkGit'], (settings) => {
        let regexes = {};
        if (settings.generics !== false) regexes = { ...regexes, ...generics };
        if (settings.specifics !== false) regexes = { ...regexes, ...specifics };
        if (settings.aws !== false) regexes = { ...regexes, ...aws };

        const parentUrl = request.parentUrl;
        const parentOrigin = request.parentOrigin;

        if (request.scriptUrl) {
            checkIfOriginDenied(request.scriptUrl, (skip) => {
                if (!skip) {
                    fetch(request.scriptUrl, { "credentials": 'include' })
                        .then(response => response.text())
                        .then(data => checkData(data, request.scriptUrl, regexes, undefined, parentUrl, parentOrigin))
                        .catch(err => console.error("Fetch failed for script:", request.scriptUrl, err));
                }
            });
        } else if (request.pageBody) {
            checkIfOriginDenied(request.origin, (skip) => {
                if (!skip) {
                    checkData(request.pageBody, request.origin, regexes, undefined, parentUrl, parentOrigin);
                }
            });
        } else if (request.envFile) {
            if (settings.checkEnv) {
                fetch(request.envFile, { "credentials": 'include' })
                    .then(response => response.text())
                    .then(data => {
                        if (data.includes("=") || data.includes("APP_") || data.includes("DB_")) {
                            checkData(data, ".env file", regexes, undefined, parentUrl, parentOrigin);
                        }
                    })
                    .catch(err => {});
            }
        } else if (request.openTabs) {
            for (let tab of request.openTabs) {
                chrome.tabs.create({ url: tab });
            }
        } else if (request.gitDir) {
            if (settings.checkGit) {
                fetch(request.gitDir, { "credentials": 'include' })
                    .then(response => response.text())
                    .then(data => checkForGitDir(data, request.gitDir))
                    .catch(err => {});
            }
        }
    });
    return true;
});
