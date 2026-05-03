// inject.js - Advanced Scanning (DOM, Shadow DOM, Mutations, Storage)

(function() {
    const currentOrigin = window.location.origin;
    const currentUrl = window.location.href;

    // 1. Recursive Shadow DOM Scanner
    function scanNode(node) {
        if (!node) return "";
        let text = "";
        
        // Get text from this node
        if (node.nodeType === Node.TEXT_NODE) {
            text += node.textContent;
        } else if (node.nodeType === Node.ELEMENT_NODE) {
            // Scan attributes (common place for secrets in data-attrs)
            for (let attr of node.attributes) {
                text += ` ${attr.name}="${attr.value}" `;
            }

            // Recurse into children
            for (let child of node.childNodes) {
                text += scanNode(child);
            }

            // Dive into Shadow DOM
            if (node.shadowRoot) {
                text += scanNode(node.shadowRoot);
            }
        }
        return text;
    }

    // 2. Debounced Full Scan
    let scanTimeout;
    function triggerScan(isMutation = false) {
        clearTimeout(scanTimeout);
        scanTimeout = setTimeout(() => {
            const pageText = scanNode(document.documentElement);
            chrome.runtime.sendMessage({
                "pageBody": pageText,
                "origin": currentOrigin,
                "parentUrl": currentUrl,
                "parentOrigin": currentOrigin,
                "isMutation": isMutation
            });
            
            if (!isMutation) {
                scanStorage();
                scanScriptsAndSourceMaps();
            }
        }, 1000);
    }

    // 3. Storage & Cookie Scanner
    function scanStorage() {
        const storageData = {
            localStorage: JSON.stringify(localStorage),
            sessionStorage: JSON.stringify(sessionStorage),
            cookies: document.cookie
        };
        chrome.runtime.sendMessage({
            "storageScan": storageData,
            "origin": currentOrigin,
            "parentUrl": currentUrl
        });
    }

    // 4. Source Map & Script Scanner
    function scanScriptsAndSourceMaps() {
        for (let script of document.scripts) {
            if (script.src) {
                let scriptSRC = script.src;
                if (scriptSRC.startsWith("//")) scriptSRC = window.location.protocol + scriptSRC;
                
                chrome.runtime.sendMessage({
                    "scriptUrl": scriptSRC,
                    "parentUrl": currentUrl,
                    "parentOrigin": currentOrigin
                });

                // Simple Source Map check: fetch first few KB to look for mapping URL
                fetch(scriptSRC, { method: 'GET', credentials: 'omit' })
                    .then(r => r.text())
                    .then(text => {
                        const mapMatch = text.match(/\/\/# sourceMappingURL=(.*)/);
                        if (mapMatch) {
                            const mapUrl = new URL(mapMatch[1], scriptSRC).href;
                            chrome.runtime.sendMessage({
                                "sourceMapUrl": mapUrl,
                                "parentUrl": currentUrl,
                                "scriptUrl": scriptSRC
                            });
                        }
                    }).catch(() => {});
            }
        }
    }

    // 5. Mutation Observer
    const observer = new MutationObserver((mutations) => {
        let shouldScan = false;
        for (let mutation of mutations) {
            if (mutation.addedNodes.length > 0) {
                shouldScan = true;
                break;
            }
        }
        if (shouldScan) triggerScan(true);
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });

    // Initial Scan
    triggerScan();

    // Environment Probing
    const pathParts = window.location.pathname.split('/');
    pathParts.pop();
    const baseUrl = currentOrigin + pathParts.join('/');
    chrome.runtime.sendMessage({ "envFile": baseUrl + "/.env", "parentUrl": currentUrl, "parentOrigin": currentOrigin });
    chrome.runtime.sendMessage({ "gitDir": baseUrl + "/.git/config", "parentUrl": currentUrl, "parentOrigin": currentOrigin });

})();
