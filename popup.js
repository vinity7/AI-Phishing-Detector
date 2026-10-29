// ============================================================
// Phishing Detector — popup.js (Detection Engine v3)
// ============================================================

// ---- Scan Button ----
document.getElementById('scanBtn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const statusEl    = document.getElementById('status');
  const threatListEl = document.getElementById('threatList');

  statusEl.innerText = '🔍 Scanning...';
  statusEl.style.backgroundColor = '#e0f2fe';
  statusEl.style.color = '#0369a1';
  threatListEl.innerHTML = '';

  chrome.scripting.executeScript(
    { target: { tabId: tab.id }, func: scanPageForPhishing },
    (results) => {
      if (chrome.runtime.lastError || !results || !results[0]) {
        statusEl.innerText = '❌ Could not scan this page.';
        statusEl.style.backgroundColor = '#f3f4f6';
        statusEl.style.color = '#374151';
        return;
      }

      const threats = results[0].result;
      const high   = threats.filter(t => t.riskScore >= 75).length;
      const medium = threats.filter(t => t.riskScore >= 60 && t.riskScore < 75).length;

      if (threats.length > 0) {
        statusEl.innerHTML =
          `⚠️ <strong>${threats.length} threat(s)</strong> found &nbsp;` +
          (high   ? `<span class="badge badge-high">${high} HIGH</span> `   : '') +
          (medium ? `<span class="badge badge-med">${medium} MEDIUM</span>` : '');
        statusEl.style.backgroundColor = '#fee2e2';
        statusEl.style.color = '#991b1b';
      } else {
        statusEl.innerText = '✅ Page clean — no threats detected.';
        statusEl.style.backgroundColor = '#d1fae5';
        statusEl.style.color = '#065f46';
      }

      // Render threat cards
      threats.forEach(t => {
        const card = document.createElement('div');
        card.className = 'threat-card ' + (t.riskScore >= 75 ? 'threat-high' : 'threat-med');
        card.innerHTML = `
          <div class="threat-type">${t.riskType}</div>
          <div class="threat-url" title="${t.url}">${t.url.length > 45 ? t.url.slice(0, 45) + '…' : t.url}</div>
          <ul class="threat-reasons">${t.reasons.map(r => `<li>${r}</li>`).join('')}</ul>
        `;
        threatListEl.appendChild(card);
      });

      chrome.storage.local.set({ detectedThreats: threats });
      chrome.runtime.sendMessage({ action: 'updateBadge', count: threats.length, high });
    }
  );
});

// ---- Export Button ----
document.getElementById('exportBtn').addEventListener('click', () => {
  chrome.storage.local.get(['detectedThreats'], (result) => {
    const threats = result.detectedThreats || [];
    const logData = JSON.stringify({
      project: 'Phishing & Malicious Link Warning System',
      author: 'Vinit Yadav (vinity7)',
      timestamp: new Date().toISOString(),
      threatCount: threats.length,
      detectedThreats: threats
    }, null, 2);

    const blob = new Blob([logData], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'Phishing_Threat_Log.json';
    a.click();
    URL.revokeObjectURL(url);
  });
});

// ============================================================
// DETECTION ENGINE — injected into the active webpage
// All constants must live INSIDE this function (isolated context)
// ============================================================
function scanPageForPhishing() {

  const URL_SHORTENERS = new Set([
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
    'adf.ly','short.link','rb.gy','cutt.ly','tiny.cc','shorte.st',
    'clck.ru','url.ie','v.gd','x.co','snipurl.com','tr.im','cli.gs'
  ]);

  const TRUSTED_BRANDS = [
    'paypal','google','apple','microsoft','amazon','facebook','instagram',
    'netflix','linkedin','twitter','dropbox','chase','bankofamerica',
    'wellsfargo','citibank','irs','usps','fedex','dhl','ebay','steam',
    'coinbase','binance','metamask','yahoo','outlook','office365'
  ];

  const PHISHING_KEYWORDS = [
    /login[-_.]?verify/i,       /account[-_.]?update/i,
    /secure[-_.]?login/i,       /verify[-_.]?account/i,
    /confirm[-_.]?identity/i,   /update[-_.]?payment/i,
    /suspended[-_.]?account/i,  /unlock[-_.]?account/i,
    /unusual[-_.]?activity/i,   /reset[-_.]?password/i,
    /billing[-_.]?info/i,       /act[-_.]?now/i,
    /credential/i,              /webscr/i,
    /signin[-_.]?required/i,    /limited[-_.]?access/i,
    /account[-_.]?compromised/i
  ];

  // Only unambiguous redirect param names.
  // Removed: "return", "target", "next", "ref_url", "out", "r", "link",
  // "continue", "callback" — all used legitimately by Amazon, Google, etc.
  const OPEN_REDIRECT_PARAMS = new Set([
    'redirect','redirect_url','redirect_uri','goto',
    'destination','forward','redirectto'
  ]);

  // Links pointing TO these root domains skip low-confidence checks entirely.
  const TRUSTED_ROOT_DOMAINS = new Set([
    'amazon.com','amazon.in','amazon.co.uk','amazon.de','amazon.ca',
    'amazon.fr','amazon.co.jp','amazon.com.au','amazon.com.mx',
    'ssl-images-amazon.com','media-amazon.com','images-amazon.com',
    'google.com','google.co.in','google.co.uk','googleapis.com','gstatic.com',
    'youtube.com','ytimg.com','googlevideo.com',
    'microsoft.com','live.com','office.com','microsoftonline.com','bing.com',
    'apple.com','icloud.com',
    'facebook.com','fbcdn.net','instagram.com','cdninstagram.com',
    'twitter.com','x.com','twimg.com',
    'linkedin.com','licdn.com',
    'github.com','githubusercontent.com',
    'wikipedia.org','wikimedia.org',
    'reddit.com','redd.it','redditmedia.com',
    'netflix.com','nflximg.net',
    'paypal.com','stripe.com','razorpay.com',
    'flipkart.com','myntra.com','snapdeal.com',
    'cloudflare.com','akamaihd.net','akamai.net',
    'jsdelivr.net','unpkg.com',
    // Amazon-owned ad/CDN domains
    'amazon-adsystem.com','amazonservices.com','assoc-amazon.com',
    'awsstatic.com','aws.amazon.com','d1.awsstatic.com'
  ]);

  function getRootDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.replace(/^www\./, '').split('.');
    return parts.length <= 2 ? parts.join('.') : parts.slice(-2).join('.');
  }

  const pageRootDomain = getRootDomain(window.location.hostname);

  function analyzeLink(link) {
    const rawHref = (link.getAttribute('href') || '').trim();
    const href    = link.href || '';
    const text    = link.innerText.trim();
    let score     = 0;
    const reasons = [];

    if (!rawHref || rawHref === '#' || rawHref.startsWith('mailto:') || rawHref.startsWith('tel:')) return null;

    // CHECK 1 — javascript: URI
    // Whitelist common no-op patterns used legitimately on every major website
    if (rawHref.toLowerCase().startsWith('javascript:')) {
      const jsBody = rawHref.replace(/^javascript:\s*/i, '').trim().replace(/;$/, '').trim();
      const NOOP_PATTERNS = ['void(0)', 'void 0', '', ';'];
      if (NOOP_PATTERNS.includes(jsBody)) return null; // harmless no-op, skip
      return { riskType: 'HIGH — javascript: URI', score: 90,
        reasons: [`Link runs inline JavaScript: "${rawHref.slice(0, 80)}" — possible XSS or phishing vector`] };
    }

    // CHECK 2 — data: URI (always flag)
    if (rawHref.toLowerCase().startsWith('data:')) {
      return { riskType: 'HIGH — data: URI link', score: 85,
        reasons: ['data: URIs can embed malicious HTML/scripts inside a link'] };
    }

    let urlObj;
    try { urlObj = new URL(href); } catch (e) { return null; }

    const hostname     = urlObj.hostname;
    const rootDomain   = getRootDomain(hostname);
    const params       = urlObj.searchParams;
    const pathAndQuery = (urlObj.pathname + urlObj.search).toLowerCase();

    // CHECK 3 — @-sign trick (always flag — no legitimate use case)
    if (urlObj.username || urlObj.password) {
      score += 85;
      reasons.push(`@-sign trick: browser navigates to "${hostname}" — text before @ is bait`);
    }

    // Trusted link destination — skip remaining heuristic checks
    if (TRUSTED_ROOT_DOMAINS.has(rootDomain)) {
      if (score < 60) return null;
    }

    // CHECK 4 — Open redirect: only flag if the embedded URL is a DIFFERENT domain
    // than both the link's own domain and the current page's domain.
    for (const [key, val] of params.entries()) {
      if (OPEN_REDIRECT_PARAMS.has(key.toLowerCase())) {
        if (/^https?:\/\//i.test(val) || val.startsWith('//')) {
          try {
            const rTarget = new URL(val.startsWith('//') ? 'https:' + val : val);
            const rRoot   = getRootDomain(rTarget.hostname);
            if (rRoot !== rootDomain && rRoot !== pageRootDomain) {
              score += 70;
              reasons.push(`Open redirect "?${key}=" silently forwards to external domain "${rRoot}"`);
            }
          } catch (_) {}
          break;
        }
      }
    }

    // CHECK 5 — URL shortener hides real destination
    if (URL_SHORTENERS.has(rootDomain) || URL_SHORTENERS.has(hostname)) {
      score += 40;
      reasons.push(`URL shortener (${hostname}) conceals where this link really goes`);
    }

    // CHECK 6 — Brand impersonation via subdomain
    // e.g. paypal.secure-login.com — root = secure-login.com, "paypal" is bait
    for (const brand of TRUSTED_BRANDS) {
      if (hostname.toLowerCase().includes(brand) && !rootDomain.toLowerCase().includes(brand)) {
        score += 80;
        reasons.push(`Brand impersonation: "${brand}" in subdomain, real domain is "${rootDomain}"`);
        break;
      }
    }

    // CHECK 7 — Punycode / homograph attack
    if (hostname.includes('xn--')) {
      score += 55;
      reasons.push(`Punycode domain "${hostname}" — Unicode lookalike chars used to spoof a trusted site`);
    }

    // CHECK 8 — Excessive subdomain depth (≥6 levels)
    // Normal CDN/cloud subdomains are 3–4 deep; 6+ is unusual and used to obfuscate
    const subdomainDepth = hostname.split('.').length;
    if (subdomainDepth >= 6) {
      score += 35;
      reasons.push(`${subdomainDepth}-level deep subdomain "${hostname}" — obfuscation tactic`);
    }

    // CHECK 9 — Phishing keywords (bonus signal — only counts when something else already flagged)
    if (score > 0) {
      for (const pattern of PHISHING_KEYWORDS) {
        if (pattern.test(pathAndQuery)) {
          score += 30;
          reasons.push(`Phishing keyword pattern in URL path: "${pattern.source}"`);
          break;
        }
      }
    }

    // CHECK 10 — Raw IP on HTTP (not HTTPS — HTTPS IPs are less immediately suspicious)
    if (/^http:\/\/\d{1,3}(\.\d{1,3}){3}(:\d+)?/.test(href)) {
      score += 60;
      reasons.push(`Unencrypted raw IP address host (${hostname}) — legitimate services use domain names`);
    }

    // CHECK 11 — Domain mismatch: visible text IS a domain, but href goes elsewhere.
    // Require exact match (^...$) to avoid matching product names or descriptions.
    if (text.length > 0 && text.length <= 40) {
      const visibleMatch = text.match(/^([a-z0-9-]+\.(com|net|org|io|gov|edu|co\.uk|in|uk))$/i);
      if (visibleMatch) {
        const visibleBrand = visibleMatch[1].split('.')[0].toLowerCase();
        if (!hostname.toLowerCase().includes(visibleBrand)) {
          score += 75;
          reasons.push(`Link text shows "${visibleMatch[1]}" but navigates to "${hostname}"`);
        }
      }
    }

    // CHECK 12 — Suspicious TLD (bonus signal only, not standalone trigger)
    if (score > 0 && /\.(tk|ml|ga|cf|gq|pw|xyz|top|club|online|site|work|click|download)$/.test(hostname)) {
      score += 20;
      reasons.push(`Suspicious free TLD ".${hostname.split('.').pop()}" — heavily abused in phishing`);
    }

    // Threshold raised to 60 to cut false positives
    if (score < 60) return null;

    const severity = score >= 75 ? 'HIGH' : 'MEDIUM';
    return { riskType: `${severity} — ${reasons[0].slice(0, 65)}`, score, reasons };
  }

  const threats = [];

  // ---- Scan anchor tags ----
  document.querySelectorAll('a[href]').forEach(link => {
    const result = analyzeLink(link);
    if (!result) return;

    threats.push({
      url:       link.href,
      text:      link.innerText.trim() || 'Unlabeled Link',
      riskType:  result.riskType,
      riskScore: result.score,
      reasons:   result.reasons
    });

    const color = result.score >= 75 ? '#dc2626' : '#d97706';
    const bg    = result.score >= 75 ? '#fee2e2' : '#fef3c7';
    link.style.outline         = `2px solid ${color}`;
    link.style.backgroundColor = bg;
    link.style.borderRadius    = '3px';
    link.title = `⚠️ ${result.riskType}\n\n${result.reasons.join('\n')}`;
  });

  // ---- Clickjacking: HIDDEN cross-origin iframes only ----
  // Unsandboxed iframes are too common on legit sites (ads, embeds, maps).
  // Only flag iframes that are invisible AND cross-origin AND not from a trusted domain.
  document.querySelectorAll('iframe').forEach(iframe => {
    const src = iframe.src || '';
    if (!src || src === 'about:blank' || src.startsWith('javascript:')) return;

    const style    = window.getComputedStyle(iframe);
    const w        = parseFloat(style.width);
    const h        = parseFloat(style.height);
    const isHidden =
      style.opacity === '0'        ||
      (w <= 1 && h <= 1)           ||
      style.display === 'none'     ||
      style.visibility === 'hidden';

    if (isHidden) {
      let iframeRoot = '';
      try { iframeRoot = getRootDomain(new URL(src).hostname); } catch (_) {}
      if (iframeRoot && iframeRoot !== pageRootDomain && !TRUSTED_ROOT_DOMAINS.has(iframeRoot)) {
        threats.push({
          url: src, text: '[Hidden iFrame]',
          riskType: 'HIGH — Clickjacking: hidden cross-origin iframe',
          riskScore: 88,
          reasons: [
            `Hidden iframe loads "${iframeRoot}" on a page from "${pageRootDomain}"`,
            'Invisible iframes can hijack your clicks — e.g. silently approving payments or social actions'
          ]
        });
      }
    }
  });

  return threats;
}