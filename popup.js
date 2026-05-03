// popup.js - Phase 3 Logic (UI Updates & False Positive Handling)

const toggles = ["generics", "specifics", "aws", "entropy", "checkEnv", "checkGit", "alerts"];

const toggleDefaults = {
    "generics": true,
    "specifics": true,
    "aws": true,
    "entropy": false,
    "checkEnv": false,
    "checkGit": false,
    "alerts": true
};

async function init() {
    // 1. Initialize Toggles
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

    // 2. Initialize Accordions
    const acc = document.getElementsByClassName("accordion");
    for (let i = 0; i < acc.length; i++) {
        acc[i].addEventListener("click", function() {
            this.classList.toggle("active");
            const panel = this.nextElementSibling;
            panel.style.display = (panel.style.display === "block") ? "none" : "block";
            
            if (panel.style.display === "block") {
                if (this.innerText.includes("Findings")) updateFindings();
                if (this.innerText.includes("Deny List")) updateDenyListUI();
            }
        });
    }

    // 3. Batch Opener
    document.getElementById("openTabs").addEventListener("click", () => {
        const list = document.getElementById("tabList").value.split(",").map(u => u.trim()).filter(u => u);
        chrome.runtime.sendMessage({ openTabs: list });
    });

    // 4. Global Actions
    document.getElementById("clearAllFindings").addEventListener("click", async () => {
        if (confirm("Clear ALL findings across all origins?")) {
            await chrome.storage.sync.set({ leakedKeys: {} });
            updateFindings();
        }
    });

    document.getElementById("clearOriginFindings").addEventListener("click", async () => {
        const origin = await getCurrentOrigin();
        const res = await chrome.storage.sync.get("leakedKeys");
        const keys = res.leakedKeys || {};
        delete keys[origin];
        await chrome.storage.sync.set({ leakedKeys: keys });
        updateFindings();
    });

    document.getElementById("downloadAllFindings").addEventListener("click", downloadCSV);

    // 5. Deny List
    document.getElementById("denyList").addEventListener("change", async (e) => {
        const list = e.target.value.split(",").map(i => i.trim()).filter(i => i);
        await chrome.storage.sync.set({ originDenyList: list });
    });

    updateFindingsBadge();
}

async function getCurrentOrigin() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs[0]?.url) return null;
    try {
        return new URL(tabs[0].url).origin;
    } catch (e) { return null; }
}

async function updateFindings() {
    const origin = await getCurrentOrigin();
    const res = await chrome.storage.sync.get("leakedKeys");
    const container = document.getElementById("findingList");
    const keys = (res.leakedKeys || {})[origin] || [];

    if (keys.length === 0) {
        container.innerHTML = '<li class="empty-state">No findings for this origin</li>';
        updateFindingsBadge();
        return;
    }

    container.innerHTML = "";
    keys.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

    keys.forEach((f, index) => {
        const li = document.createElement("li");
        li.className = "finding-item";
        li.innerHTML = `
            <div class="finding-header">
                <span>${htmlEntities(f.key)}</span>
                <small>${new Date(f.timestamp || Date.now()).toLocaleTimeString()}</small>
            </div>
            <div class="finding-match">${htmlEntities(f.match)}</div>
            ${f.context ? `<div class="finding-context">...${htmlEntities(f.context)}...</div>` : ''}
            <div class="finding-actions">
                <button class="btn secondary small ignore-btn" data-match="${htmlEntities(f.match)}">Ignore</button>
                <button class="btn secondary small copy-btn" data-match="${htmlEntities(f.match)}">Copy</button>
            </div>
        `;
        container.appendChild(li);
    });

    // Add event listeners to new buttons
    container.querySelectorAll(".ignore-btn").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            const match = e.target.getAttribute("data-match");
            if (confirm(`Ignore this value globally?`)) {
                const s = await chrome.storage.sync.get("globalIgnoreList");
                const list = s.globalIgnoreList || [];
                list.push(match);
                await chrome.storage.sync.set({ globalIgnoreList: list });
                // Also remove from current findings
                await removeFindingGlobally(match);
                updateFindings();
            }
        });
    });

    container.querySelectorAll(".copy-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const match = e.target.getAttribute("data-match");
            navigator.clipboard.writeText(match);
            e.target.innerText = "Copied!";
            setTimeout(() => e.target.innerText = "Copy", 1000);
        });
    });

    updateFindingsBadge();
}

async function removeFindingGlobally(matchValue) {
    const res = await chrome.storage.sync.get("leakedKeys");
    const keys = res.leakedKeys || {};
    for (let origin in keys) {
        keys[origin] = keys[origin].filter(f => f.match !== matchValue);
    }
    await chrome.storage.sync.set({ leakedKeys: keys });
}

async function updateFindingsBadge() {
    const origin = await getCurrentOrigin();
    const res = await chrome.storage.sync.get("leakedKeys");
    const count = ((res.leakedKeys || {})[origin] || []).length;
    document.getElementById("findingsBadge").innerText = count;
}

async function updateDenyListUI() {
    const res = await chrome.storage.sync.get("originDenyList");
    document.getElementById("denyList").value = (res.originDenyList || []).join(", ");
}

function htmlEntities(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function downloadCSV() {
    const res = await chrome.storage.sync.get("leakedKeys");
    const keys = res.leakedKeys || {};
    let rows = [["Origin", "Type", "Match", "Source", "Parent URL"]];
    
    for (let origin in keys) {
        keys[origin].forEach(f => {
            rows.push([origin, f.key, f.match, f.src, f.parentUrl]);
        });
    }

    const content = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([content], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `trufflehog_findings_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
}

init();
