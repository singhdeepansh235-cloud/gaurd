document.addEventListener("DOMContentLoaded", async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url) {
        document.getElementById("url").innerText = "Cannot read URL";
        document.getElementById("result-text").innerText = "Unavailable";
        return;
    }
    
    let url = tab.url;
    document.getElementById("url").innerText = url;
    document.getElementById("url").title = url;
    
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        document.getElementById("result-box").className = "result-box status-safe";
        document.getElementById("result-text").innerText = "Internal Page";
        return;
    }

    checkPhishing(url);
});

async function checkPhishing(url) {
    try {
        // Hitting the existing Sentiment-Fuzz backend running locally
        let response = await fetch("http://127.0.0.1:8080/api/phishing-check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ target: url })
        });

        if (!response.ok) {
            throw new Error(`Server responded with ${response.status}`);
        }

        let data = await response.json();
        
        const resultBox = document.getElementById("result-box");
        const resultText = document.getElementById("result-text");
        const scoreContainer = document.getElementById("score-container");
        const scoreBar = document.getElementById("score-bar");
        const scoreValue = document.getElementById("score-value");
        const reasonsList = document.getElementById("reasons-list");
        
        // Update Verdict
        let status = data.phishing?.status || "Unknown";
        resultText.innerText = status;
        
        // Use risk_score if available (Live/AI adjusted), else heuristic confidence
        let riskScore = data.risk_score !== undefined ? data.risk_score : (data.phishing?.confidence || 0);
        
        if (riskScore >= 55 || status === "Likely Phishing") {
            resultBox.className = "result-box status-phishing";
            scoreBar.style.background = "#f38ba8";  // Red
        } else if (riskScore >= 25 || status === "Suspicious") {
            resultBox.className = "result-box status-suspicious";
            scoreBar.style.background = "#f9e2af";  // Yellow
        } else {
            resultBox.className = "result-box status-safe";
            scoreBar.style.background = "#a6e3a1";  // Green
        }
        
        // Update Score UI
        scoreContainer.style.display = "block";
        
        // Small delay to allow CSS transition to animate the bar
        setTimeout(() => {
            scoreBar.style.width = `${riskScore}%`;
        }, 100);
        
        scoreValue.innerText = `${Math.round(riskScore)}/100`;
        
        // Compile reasons (combine heuristic and live)
        let reasons = data.phishing?.reasons || [];
        if (data.live_checks && data.live_checks.live_reasons) {
            reasons = [...reasons, ...data.live_checks.live_reasons];
        }
        
        // Render top reasons
        if (reasons.length > 0) {
            reasonsList.style.display = "block";
            reasonsList.innerHTML = '';
            
            // Deduplicate reasons
            reasons = [...new Set(reasons)];
            
            reasons.slice(0, 4).forEach(reason => {
                let li = document.createElement("li");
                li.innerText = reason;
                reasonsList.appendChild(li);
            });
            
            if (reasons.length > 4) {
                let li = document.createElement("li");
                li.innerText = `+ ${reasons.length - 4} more internal flags...`;
                li.style.fontStyle = "italic";
                reasonsList.appendChild(li);
            }
        }

    } catch (e) {
        document.getElementById("result-box").className = "result-box status-checking";
        document.getElementById("result-text").innerText = "Backend Offline";
        document.getElementById("error-msg").style.display = "block";
        console.error("Phishing check failed:", e);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const geminiBtn = document.getElementById("gemini-btn");
    if (geminiBtn) {
        geminiBtn.addEventListener("click", async () => {
            let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab || !tab.url) return;
            
            const resBox = document.getElementById("gemini-result");
            geminiBtn.innerText = "Analyzing...";
            geminiBtn.disabled = true;
            resBox.style.display = "block";
            resBox.innerText = "Processing AI analysis... Please wait.";
            
            try {
                let response = await fetch("http://127.0.0.1:8080/api/gemini-report", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ target: tab.url })
                });
                
                if (!response.ok) {
                    throw new Error("Server error");
                }
                
                let data = await response.json();
                
                if (data.enabled === false) {
                    resBox.innerText = data.summary || "AI Analysis unavailable.";
                } else {
                    resBox.innerHTML = `<strong>Verdict:</strong> ${data.verdict}<br><br><strong>Summary:</strong> ${data.summary}`;
                }
            } catch(e) {
                resBox.innerText = "Error contacting backend for AI analysis.";
                console.error(e);
            }
            
            geminiBtn.innerText = "🤖 Trigger AI Analysis";
            geminiBtn.disabled = false;
        });
    }
});
