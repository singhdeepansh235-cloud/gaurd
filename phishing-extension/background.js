// Background script to monitor navigation and auto-check for phishing

// Listen for tab updates (page loads)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        checkPhishingBackground(tab.url, tabId);
    }
});

async function checkPhishingBackground(url, tabId) {
    if (!url || !url.startsWith("http")) {
        return; 
    }

    try {
        let response = await fetch("http://127.0.0.1:8080/api/phishing-check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ target: url })
        });
        
        if (!response.ok) return;
        
        let data = await response.json();
        
        let status = data.phishing?.status || "Safe";
        let riskScore = data.risk_score !== undefined ? data.risk_score : (data.phishing?.confidence || 0);
        
        if (riskScore >= 55 || status === "Likely Phishing") {
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#f38ba8" });
            chrome.action.setBadgeText({ tabId, text: "!" });
        } else if (riskScore >= 25 || status === "Suspicious") {
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#f9e2af" });
            chrome.action.setBadgeText({ tabId, text: "?" });
        } else {
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#a6e3a1" });
            chrome.action.setBadgeText({ tabId, text: "✓" });
            
            // Clear safe badge after 4 seconds to reduce visual noise
            setTimeout(() => {
                chrome.action.setBadgeText({ tabId, text: "" });
            }, 4000);
        }

    } catch (e) {
        // Silent failure if backend is dead in background script
        console.error("Background check failed:", e);
    }
}
