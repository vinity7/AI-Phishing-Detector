chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "updateBadge") {
    const badgeText = request.count > 0 ? request.count.toString() : "SAFE";
    chrome.action.setBadgeText({ text: badgeText });
    chrome.action.setBadgeBackgroundColor({ 
      color: request.count > 0 ? "#DC2626" : "#059669" 
    });
  }
});// Feature: Dynamic toolbar badge counter
