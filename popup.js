// popup.js for Manifest V3

const toggles = ["generics", "specifics", "aws", "checkEnv", "checkGit", "alerts"];

const toggleDefaults = {
    "generics": true,
    "specifics": true,
    "aws": true,
    "checkEnv": false,
    "checkGit": false,
    "alerts": true
};

async function initToggles() {
    for (let toggle of toggles) {
        const result = await chrome.storage.sync.get([toggle]);
        const element = document.getElementById(toggle);
        if (result[toggle] === undefined) {
            element.checked = toggleDefaults[toggle];
            await chrome.storage.sync.set({ [toggle]: toggleDefaults[toggle] });
        } else {
            element.checked = result[toggle];
        }

        element.addEventListener('change', async () => {
            await chrome.storage.sync.set({ [toggle]: element.checked });
        });
    }
}

function htmlEntities(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function updateFindings() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length === 0) return;
    const tab = tabs[0];
    if (!tab.url) return;

    try {
        const origin = new URL(tab.url).origin;
        const result = await chrome.storage.sync.get(["leakedKeys"]);
        const leakedKeys = result.leakedKeys || {};
        const keys = leakedKeys[origin] || [];
        
        let htmlList = "";
        for (let key of keys) {
            let keyInfo = `${key.key}: ${key.match} found in ${key.src}`;
            if (key.encoded) {
                keyInfo += ` decoded from ${key.encoded.substring(0, 9)}...`;
            }
            htmlList += `<li>${htmlEntities(keyInfo)}</li>\n`;
        }
        document.getElementById("findingList").innerHTML = htmlList || "<li>No findings for this origin</li>";
    } catch (e) {
        document.getElementById("findingList").innerHTML = "<li>Cannot scan this page type</li>";
    }
}

const acc = document.getElementsByClassName("accordion");
for (let i = 0; i < acc.length; i++) {
    acc[i].addEventListener("click", async function() {
        this.classList.toggle("active");
        const panel = this.nextElementSibling;
        if (panel.style.display === "block") {
            panel.style.display = "none";
        } else {
            panel.style.display = "block";
            if (this.innerText.includes("Findings")) {
                await updateFindings();
            } else if (this.innerText.includes("Deny List")) {
                const result = await chrome.storage.sync.get(["originDenyList"]);
                document.getElementById("denyList").value = (result.originDenyList || []).join(",");
            }
        }
    });
}

document.getElementById("downloadAllFindings").addEventListener("click", async () => {
    const result = await chrome.storage.sync.get(["leakedKeys"]);
    const leakedKeys = result.leakedKeys || {};
    let csvRows = [["Origin", "Source", "Parent URL", "Key Type", "Match", "Encoded From"]];
    
    for (let origin in leakedKeys) {
        for (let finding of leakedKeys[origin]) {
            csvRows.push([
                origin,
                finding.src,
                finding.parentUrl,
                finding.key,
                finding.match,
                finding.encoded || ""
            ]);
        }
    }
    
    const csvContent = csvRows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "trufflehog_findings.csv");
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
});

document.getElementById("clearOriginFindings").addEventListener("click", async () => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length === 0) return;
    const origin = new URL(tabs[0].url).origin;
    
    const result = await chrome.storage.sync.get(["leakedKeys"]);
    const leakedKeys = result.leakedKeys || {};
    delete leakedKeys[origin];
    await chrome.storage.sync.set({ "leakedKeys": leakedKeys });
    
    chrome.action.setBadgeText({ text: '' });
    document.getElementById("findingList").innerHTML = "<li>No findings for this origin</li>";
});

document.getElementById("clearAllFindings").addEventListener("click", async () => {
    await chrome.storage.sync.set({ "leakedKeys": {} });
    chrome.action.setBadgeText({ text: '' });
    document.getElementById("findingList").innerHTML = "<li>No findings for this origin</li>";
});

document.getElementById("openTabs").addEventListener("click", () => {
    const rawTabList = document.getElementById("tabList").value;
    const tabList = rawTabList.split(",").map(item => item.trim()).filter(item => item !== "");
    chrome.runtime.sendMessage({ "openTabs": tabList });
});

const denyListElement = document.getElementById("denyList");
const updateDenyList = async () => {
    const rawDenyList = denyListElement.value;
    const denyList = rawDenyList.split(",").map(item => item.trim()).filter(item => item !== "");
    await chrome.storage.sync.set({ "originDenyList": denyList });
};

denyListElement.addEventListener('keyup', updateDenyList);
denyListElement.addEventListener('paste', updateDenyList);

initToggles();
