// popup.js - Pro Features (Webhook settings & Advanced UI)

const toggles = ["generics", "specifics", "entropy", "checkEnv", "alerts"];

async function init() {
    // 1. Initialize Toggles
    for (let toggle of toggles) {
        const result = await chrome.storage.sync.get([toggle]);
        const element = document.getElementById(toggle);
        if (result[toggle] !== undefined) {
            element.checked = result[toggle];
        } else {
            // Default states
            element.checked = (toggle === 'generics' || toggle === 'specifics' || toggle === 'alerts');
        }

        element.addEventListener('change', async () => {
            await chrome.storage.sync.set({ [toggle]: element.checked });
        });
    }

    // 2. Webhook Settings
    const webhookRes = await chrome.storage.sync.get("webhookUrl");
    if (webhookRes.webhookUrl) {
        document.getElementById("webhookUrl").value = webhookRes.webhookUrl;
    }
    document.getElementById("saveWebhook").addEventListener("click", async () => {
        const url = document.getElementById("webhookUrl").value;
        await chrome.storage.sync.set({ webhookUrl: url });
        alert("Webhook URL saved.");
    });

    // 3. Accordions
    const acc = document.getElementsByClassName("accordion");
    for (let i = 0; i < acc.length; i++) {
        acc[i].addEventListener("click", function() {
            this.classList.toggle("active");
            const panel = this.nextElementSibling;
            panel.style.display = (panel.style.display === "block") ? "none" : "block";
            if (panel.style.display === "block" && this.innerText.includes("Findings")) updateFindings();
        });
    }

    // 4. Batch Actions
    document.getElementById("openTabs").addEventListener("click", () => {
        const list = document.getElementById("tabList").value.split(",").map(u => u.trim()).filter(u => u);
        chrome.runtime.sendMessage({ openTabs: list });
    });

    document.getElementById("clearAllFindings").addEventListener("click", async () => {
        if (confirm("Clear all findings?")) {
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

    updateFindingsBadge();
}

async function getCurrentOrigin() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs[0]?.url) return null;
    try { return new URL(tabs[0].url).origin; } catch (e) { return null; }
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
    keys.sort((a, b) => b.timestamp - a.timestamp).forEach(f => {
        const li = document.createElement("li");
        li.className = "finding-item";
        li.innerHTML = `
            <div class="finding-header">
                <span>${htmlEntities(f.key)}</span>
                <small>${new Date(f.timestamp).toLocaleTimeString()}</small>
            </div>
            <div class="finding-match">${htmlEntities(f.match)}</div>
            <div class="finding-context">...${htmlEntities(f.context)}...</div>
            <div style="font-size:10px; color:#888; margin-top:4px;">Source: ${htmlEntities(f.src)}</div>
            <div class="finding-actions">
                <button class="btn secondary small ignore-btn" data-match="${htmlEntities(f.match)}">Ignore</button>
                <button class="btn secondary small copy-btn" data-match="${htmlEntities(f.match)}">Copy</button>
            </div>
        `;
        container.appendChild(li);
    });

    container.querySelectorAll(".ignore-btn").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            const match = e.target.getAttribute("data-match");
            const s = await chrome.storage.sync.get("globalIgnoreList");
            const list = s.globalIgnoreList || [];
            list.push(match);
            await chrome.storage.sync.set({ globalIgnoreList: list });
            updateFindings();
        });
    });

    container.querySelectorAll(".copy-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            navigator.clipboard.writeText(e.target.getAttribute("data-match"));
            e.target.innerText = "Copied!";
        });
    });

    updateFindingsBadge();
}

async function updateFindingsBadge() {
    const origin = await getCurrentOrigin();
    const res = await chrome.storage.sync.get("leakedKeys");
    const count = ((res.leakedKeys || {})[origin] || []).length;
    document.getElementById("findingsBadge").innerText = count;
}

function htmlEntities(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function downloadCSV() {
    const res = await chrome.storage.sync.get("leakedKeys");
    const keys = res.leakedKeys || {};
    let rows = [["Origin", "Type", "Match", "Source"]];
    for (let origin in keys) {
        keys[origin].forEach(f => rows.push([origin, f.key, f.match, f.src]));
    }
    const content = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([content], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "trufflehog_export.csv";
    a.click();
}

init();
