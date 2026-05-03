// inject.js for Manifest V3

(function() {
    const page = document.documentElement.innerHTML;
    const currentOrigin = window.location.origin;
    const currentUrl = window.location.href;

    chrome.runtime.sendMessage({
        "pageBody": page,
        "origin": currentOrigin,
        "parentUrl": currentUrl,
        "parentOrigin": currentOrigin
    });

    // Check for scripts after a delay to allow dynamic loading
    setTimeout(() => {
        for (let script of document.scripts) {
            if (script.src) {
                let scriptSRC = script.src;
                if (scriptSRC.startsWith("//")) {
                    scriptSRC = window.location.protocol + scriptSRC;
                }
                chrome.runtime.sendMessage({
                    "scriptUrl": scriptSRC,
                    "parentUrl": currentUrl,
                    "parentOrigin": currentOrigin
                });
            }
        }
    }, 2000);

    // Try to guess .env and .git locations based on current path
    const pathParts = window.location.pathname.split('/');
    pathParts.pop(); // Remove last segment
    const basePath = pathParts.join('/');
    const baseUrl = currentOrigin + basePath;

    chrome.runtime.sendMessage({
        "envFile": baseUrl + "/.env",
        "parentUrl": currentUrl,
        "parentOrigin": currentOrigin
    });

    chrome.runtime.sendMessage({
        "gitDir": baseUrl + "/.git/config",
        "parentUrl": currentUrl,
        "parentOrigin": currentOrigin
    });
})();
