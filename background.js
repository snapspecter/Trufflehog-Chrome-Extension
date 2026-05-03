// background.js - Enterprise Edition (Network, Webhooks, SourceMaps, Checks)

const specifics = {
    "Slack Token": "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "GitHub Personal Access Token": "ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth Access Token": "gho_[a-zA-Z0-9]{36}",
    "Google Cloud API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Json Web Token": "eyJhbGciOiJ[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+\\.[a-zA-Z0-9\\-_]+",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "SendGrid API Key": "SG\\.[a-zA-Z0-9\\-_]{22}\\.[a-zA-Z0-9\\-_]{43}"
};

const generics = {
    "Generic API Key": "([aA][pP][iI]_?[kK][eE][yY]|[sS][eE][cC][rR][eE][tT]|[tT][oO][kK][eE][nN]).{0,20}['|\"]([0-9a-zA-Z\\-_]{32,45})['|\"]",
    "Bearer Token": "[bB][eE][aA][rR][eE][rR]\\s+([a-zA-Z0-9\\-\\._~\\+\\/]{20,})",
};

// --- UTILITIES ---

function luhnCheck(num) {
    let arr = (num + '').split('').reverse().map(x => parseInt(x));
    let lastDigit = arr.splice(0, 1)[0];
    let sum = arr.reduce((acc, val, i) => (i % 2 !== 0) ? acc + val : acc + ((val * 2 > 9) ? val * 2 - 9 : val * 2), 0);
    return (sum + lastDigit) % 10 === 0;
}

function shannonEntropy(str) {
    if (!str) return 0;
    let entropy = 0, len = str.length, freqs = {};
    for (let i = 0; i < len; i++) freqs[str[i]] = (freqs[str[i]] || 0) + 1;
    for (let c in freqs) { let p = freqs[c] / len; entropy -= p * Math.log2(p); }
    return entropy;
}

async function sendToWebhook(finding) {
    const s = await chrome.storage.sync.get("webhookUrl");
    if (!s.webhookUrl) return;
    try {
        await fetch(s.webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                event: "secret_detected",
                timestamp: new Date().toISOString(),
                ...finding
            })
        });
    } catch (e) { console.error("Webhook failed", e); }
}

// --- CORE SCANNING ---

const checkData = async (data, src, regexes, fromEncoded = false, parentUrl = undefined, parentOrigin = undefined) => {
    let findings = [];
    const storage = await chrome.storage.sync.get(["globalIgnoreList", "leakedKeys", "entropy"]);
    const ignoreList = storage.globalIgnoreList || [];
    
    for (let key in regexes) {
        let pattern = regexes[key];
        let re = new RegExp(pattern, 'gi');
        let match;
        while ((match = re.exec(data)) !== null) {
            let matchStr = match[2] || match[1] || match[0];
            if (ignoreList.includes(matchStr)) continue;

            const start = Math.max(0, match.index - 50);
            const context = data.substring(start, Math.min(data.length, match.index + match[0].length + 50));

            findings.push({
                src, match: matchStr, key, context,
                encoded: fromEncoded, parentUrl, parentOrigin,
                timestamp: Date.now()
            });
        }
    }

    if (storage.entropy) {
        const words = data.match(/[a-zA-Z0-9+/=]{20,}/g) || [];
        for (let word of words) {
            if (shannonEntropy(word) > 4.5 && !findings.some(f => f.match === word) && !ignoreList.includes(word)) {
                findings.push({
                    src, match: word, key: "High Entropy String",
                    context: data.substring(data.indexOf(word)-20, data.indexOf(word)+word.length+20),
                    parentUrl, parentOrigin, timestamp: Date.now()
                });
            }
        }
    }

    if (findings.length > 0) {
        let keys = storage.leakedKeys || {};
        for (let finding of findings) {
            if (!keys[parentOrigin]) keys[parentOrigin] = [];
            if (!keys[parentOrigin].some(k => k.match === finding.match)) {
                keys[parentOrigin].push(finding);
                await chrome.storage.sync.set({ "leakedKeys": keys });
                sendToWebhook(finding);
                updateTabAndAlert(finding);
            }
        }
    }
};

// --- NETWORK SCANNING (XHR/FETCH HEADERS) ---

chrome.webRequest.onBeforeSendHeaders.addListener(
    (details) => {
        const headersString = details.requestHeaders.map(h => `${h.name}: ${h.value}`).join("\n");
        checkData(headersString, `Network Request: ${details.url}`, { ...specifics, ...generics }, false, details.url, new URL(details.url).origin);
    },
    { urls: ["<all_urls>"] },
    ["requestHeaders"]
);

// --- MESSAGE HANDLING ---

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    chrome.storage.sync.get(['generics', 'specifics', 'aws', 'checkEnv', 'checkGit'], (settings) => {
        let regexes = {
            ...(settings.generics !== false ? generics : {}),
            ...(settings.specifics !== false ? specifics : {})
        };

        if (request.pageBody) {
            checkData(request.pageBody, request.origin, regexes, false, request.parentUrl, request.parentOrigin);
        } else if (request.storageScan) {
            checkData(JSON.stringify(request.storageScan), "Browser Storage", regexes, false, request.parentUrl, request.origin);
        } else if (request.scriptUrl) {
            fetch(request.scriptUrl).then(r => r.text()).then(d => checkData(d, request.scriptUrl, regexes, false, request.parentUrl, request.parentOrigin)).catch(()=>{});
        } else if (request.sourceMapUrl) {
            fetch(request.sourceMapUrl).then(r => r.text()).then(d => checkData(d, "Source Map: " + request.sourceMapUrl, regexes, false, request.parentUrl, request.parentOrigin)).catch(()=>{});
        } else if (request.envFile && settings.checkEnv) {
            fetch(request.envFile).then(r => r.text()).then(d => { if(d.includes("=")) checkData(d, ".env file", regexes, false, request.parentUrl, request.parentOrigin); }).catch(()=>{});
        } else if (request.openTabs) {
            request.openTabs.forEach(url => chrome.tabs.create({ url }));
        }
    });
    return true;
});

const updateTabAndAlert = (finding) => {
    chrome.storage.sync.get(["alerts"], (r) => {
        if (r.alerts !== false) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon48.png',
                title: 'Secret Detected!',
                message: `${finding.key} found in ${finding.src}`,
                priority: 2
            });
        }
    });
    updateTabBadge();
};

const updateTabBadge = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs[0]?.url) return;
        try {
            const origin = new URL(tabs[0].url).origin;
            chrome.storage.sync.get("leakedKeys", (res) => {
                const count = ((res.leakedKeys || {})[origin] || []).length;
                chrome.action.setBadgeText({ text: count > 0 ? count.toString() : "" });
                chrome.action.setBadgeBackgroundColor({ color: '#E53935' });
            });
        } catch(e) {}
    });
};

chrome.tabs.onActivated.addListener(updateTabBadge);
chrome.tabs.onUpdated.addListener(updateTabBadge);
