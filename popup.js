document.getElementById('scanBtn').addEventListener('click', async () => {
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: scanPageForPhishing
  }, (results) => {
    if (results && results[0]) {
      const threats = results[0].result;
      const threatCount = threats.length;
      
      const statusEl = document.getElementById('status');
      if (threatCount > 0) {
        statusEl.innerText = `⚠️ Found ${threatCount} suspicious links!`;
        statusEl.style.backgroundColor = "#fee2e2";
        statusEl.style.color = "#991b1b";
      } else {
        statusEl.innerText = `✅ Page clean! No threats found.`;
        statusEl.style.backgroundColor = "#d1fae5";
        statusEl.style.color = "#065f46";
      }

      // Save detected threats for export
      chrome.storage.local.set({ detectedThreats: threats });

      // Update extension toolbar badge
      chrome.runtime.sendMessage({ action: "updateBadge", count: threatCount });
    }
  });
});

document.getElementById('exportBtn').addEventListener('click', () => {
  chrome.storage.local.get(["detectedThreats"], (result) => {
    const threats = result.detectedThreats || [];
    const logData = JSON.stringify({
      project: "AI Phishing & Malicious Link Warning System",
      author: "Vinit Yadav (vinity7)",
      timestamp: new Date().toISOString(),
      threatCount: threats.length,
      detectedThreats: threats
    }, null, 2);

    const blob = new Blob([logData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = "Phishing_Threat_Log.json";
    a.click();
  });
});

function scanPageForPhishing() {
  const links = document.querySelectorAll('a');
  let threats = [];

  links.forEach(link => {
    const href = link.href;
    let riskType = null;

    // Check 1: Raw IP host addresses
    if (/http:\/\/\d+\.\d+\.\d+\.\d+/.test(href)) {
      riskType = "IP Address Host Detected";
    }
    // Check 2: Deceptive keyword mismatches
    else if (href.includes("login-verify") || href.includes("account-update-security")) {
      riskType = "Deceptive Keyword Pattern";
    }

    if (riskType) {
      threats.push({
        url: href,
        text: link.innerText.trim() || "Unlabeled Link",
        riskType: riskType
      });
      // Highlight on page
      link.style.border = "2px solid red";
      link.style.backgroundColor = "#fee2e2";
      link.title = `⚠️ Phishing Risk: ${riskType}`;
    }
  });

  return threats;
}