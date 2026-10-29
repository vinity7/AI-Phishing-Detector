// ============================================================
// AI Phishing Detector — background.js (Service Worker)
// ============================================================

// ---- Badge update from popup scan results ----
chrome.runtime.onMessage.addListener((request) => {
  if (request.action === 'updateBadge') {
    const count = request.count || 0;
    const high = request.high || 0;

    if (count === 0) {
      chrome.action.setBadgeText({ text: '✓' });
      chrome.action.setBadgeBackgroundColor({ color: '#059669' });
    } else {
      chrome.action.setBadgeText({ text: String(count) });
      chrome.action.setBadgeBackgroundColor({ color: high > 0 ? '#DC2626' : '#D97706' });
    }
  }
});

// ---- Redirect chain detection via webNavigation ----
// Tracks server-side redirects (301/302) and cross-origin forwards.
// Stores flagged redirects in chrome.storage so the popup can export them.
chrome.webNavigation.onCommitted.addListener((details) => {
  // Only care about top-level navigation triggered by clicking a link
  if (details.frameId !== 0) return;
  if (!details.transitionQualifiers) return;

  const isServerRedirect = details.transitionQualifiers.includes('server_redirect');
  const isClientRedirect = details.transitionQualifiers.includes('client_redirect');

  if (isServerRedirect || isClientRedirect) {
    chrome.storage.local.get(['redirectLog'], (result) => {
      const log = result.redirectLog || [];
      log.push({
        type: isServerRedirect ? 'Server Redirect (301/302)' : 'Client Redirect (JS/meta)',
        finalUrl: details.url,
        tabId: details.tabId,
        timestamp: new Date().toISOString()
      });
      // Keep last 50 redirect events
      if (log.length > 50) log.shift();
      chrome.storage.local.set({ redirectLog: log });
    });

    // Warn with badge if redirect goes cross-origin
    try {
      const url = new URL(details.url);
      chrome.tabs.get(details.tabId, (tab) => {
        if (!tab || !tab.url) return;
        try {
          const tabUrl = new URL(tab.url);
          const tabRoot = getRootDomain(tabUrl.hostname);
          const destRoot = getRootDomain(url.hostname);
          if (tabRoot && destRoot && tabRoot !== destRoot) {
            // Cross-origin redirect — flash the badge
            chrome.action.setBadgeText({ text: '↪' });
            chrome.action.setBadgeBackgroundColor({ color: '#D97706' });
          }
        } catch (_) { }
      });
    } catch (_) { }
  }
});

function getRootDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.replace(/^www\./, '').split('.');
  return parts.length <= 2 ? parts.join('.') : parts.slice(-2).join('.');
}