const tabTelemetry = {};

const PHISHING_URL_PATTERNS = [
  /login.*\.(?:xyz|top|club|gq|ml|tk|cf|ga|work|review|life|live|online|site|website|space|press|host|stream|download|bid|trade|webcam|science|party|racing|win|date|men|loan|click|faith|moe)/i,
  /secure.*\.(?:xyz|top|club|gq|ml|tk|cf|ga)/i,
  /account.*\.(?:xyz|top|gq|ml|tk|cf|ga|review|life)/i,
  /verify.*\.(?:xyz|top|gq|ml|tk|cf|ga|review)/i,
  /signin.*\.(?:xyz|top|gq|ml|tk|cf|ga)/i,
  /update.*\.(?:xyz|top|gq|ml|tk|cf|ga)/i,
  /bank.*\.(?:xyz|top|club|gq|ml|tk|cf|ga|review)/i,
  /paypal.*\.(?:xyz|top|club|gq|ml|tk|ga)/i,
  /amazon.*\.(?:xyz|top|club|gq|ml|tk|ga|review)/i,
  /netflix.*\.(?:xyz|top|club|gq|ml|tk|ga)/i,
  /(?:paypa1|paypaI|arnazon|arnaz0n|netf1ix|g00gle|faceb00k|micros0ft|app1e|whatsapp|instagrarn)/i
];

const LOW_CRED_TLDS = [
  'xyz', 'top', 'club', 'gq', 'ml', 'tk', 'cf', 'ga', 'work',
  'review', 'loan', 'win', 'bid', 'trade', 'webcam', 'science',
  'party', 'racing', 'date', 'men', 'click', 'faith', 'moe',
  'download', 'stream', 'host', 'site', 'online', 'space', 'press'
];

// Download Protection
const DANGEROUS_EXTS = {
  executables: { exe:6, msi:6, scr:6, bat:6, cmd:6, vbs:6, ps1:6, psm1:6, psd1:6, jar:6, com:6, pif:6, gadget:6, application:6 },
  scripts: { js:5, jse:5, vbe:5, wsf:5, wsh:5, hta:5, cpl:5, reg:5 },
  archives: { zip:3, rar:3, '7z':3, iso:3, cab:3, img:3 },
  macros: { docm:4, xlsm:4, pptm:4 }
};
function getExtRisk(ext) {
  for (const group of Object.values(DANGEROUS_EXTS)) {
    if (ext in group) return group[ext];
  }
  return 0;
}

let downloadStats = { totalBlocked: 0, totalWarned: 0, recentBlocks: [] };

function checkDownloadRisk(item) {
  let score = 0;
  let reasons = [];
  try {
    const filename = item.filename || item.suggestedFilename || '';
    const ext = filename.split('.').pop().toLowerCase().replace(/[^a-z0-9]/g, '');
    const extRisk = getExtRisk(ext);
    if (extRisk > 0) { score += extRisk; reasons.push('Extension .' + ext + ' (risk ' + extRisk + ')'); }
    const url = item.url || '';
    if (url) {
      const urlObj = new URL(url);
      const host = urlObj.hostname.toLowerCase();
      const tld = host.split('.').pop();
      if (LOW_CRED_TLDS.includes(tld)) { score += 4; reasons.push('Low-cred TLD: .' + tld); }
      if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) { score += 3; reasons.push('IP-based host'); }
      for (const pattern of PHISHING_URL_PATTERNS) {
        if (pattern.test(host) || pattern.test(url.toLowerCase())) { score += 5; reasons.push('Matches phishing pattern'); break; }
      }
    }
    const name = filename.toLowerCase().replace(/\.[^.]+$/, '');
    if (/^[a-z0-9]{16,}$/.test(name)) { score += 4; reasons.push('Randomized filename'); }
    const dotCount = (filename.match(/\./g) || []).length;
    if (dotCount >= 2 && ext !== 'txt' && ext !== 'pdf' && ext !== 'jpg' && ext !== 'png') { score += 4; reasons.push('Double extension'); }
  } catch (e) {}
  return { score, reasons };
}

function getMainDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  const twoPartTlds = ['co.uk','co.jp','com.au','co.nz','co.in','co.za','com.br','org.uk','ac.uk','gov.uk','net.au','org.au'];
  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTlds.includes(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function loadSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['sitesentinel_settings'], (result) => {
      const defaults = { realtime: true, email: true, notifications: false, dataCollection: true, whitelist: [], downloadProtection: true };
      resolve({ ...defaults, ...result.sitesentinel_settings });
    });
  });
}

function isWhitelisted(domain, settings) {
  const whitelist = settings.whitelist || [];
  return whitelist.some(w => domain === w || domain.endsWith('.' + w));
}

function checkUrlPhishingRisk(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const fullUrl = url.toLowerCase();

    for (const pattern of PHISHING_URL_PATTERNS) {
      if (pattern.test(hostname) || pattern.test(fullUrl)) {
        return { risk: 'high', reason: 'Matches known phishing URL pattern' };
      }
    }

    const tld = hostname.split('.').pop();
    if (LOW_CRED_TLDS.includes(tld)) {
      return { risk: 'medium', reason: 'Low-credibility TLD: .' + tld };
    }

    if (urlObj.protocol !== 'https:') {
      return { risk: 'low', reason: 'Not using HTTPS' };
    }

    return { risk: 'none', reason: '' };
  } catch (e) {
    return { risk: 'none', reason: '' };
  }
}

function getBadgeParams(risk) {
  switch (risk) {
    case 'high': return { text: '!', color: '#dc2626', title: 'Site Sentinel: Phishing risk detected' };
    case 'medium': return { text: '?', color: '#d97706', title: 'Site Sentinel: Suspicious site' };
    case 'low': return { text: '', color: '', title: 'Site Sentinel: Active' };
    default: return { text: '', color: '', title: 'Site Sentinel' };
  }
}

async function updateBadgeForTab(tabId, url) {
  if (!url || !tabId) return;
  const settings = await loadSettings();
  try {
    const domain = new URL(url).hostname;
    if (isWhitelisted(domain, settings)) {
      chrome.action.setBadgeText({ tabId, text: '' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#22c55e' });
      return;
    }
  } catch (e) {}

  const phishingResult = checkUrlPhishingRisk(url);
  const params = getBadgeParams(phishingResult.risk);
  chrome.action.setBadgeText({ tabId, text: params.text });
  if (params.color) {
    chrome.action.setBadgeBackgroundColor({ tabId, color: params.color });
  }
  if (params.title) {
    chrome.action.setTitle({ tabId, title: params.title });
  }
}

function checkStoredWarning(tabId, url) {
  try {
    const domain = new URL(url).hostname;
    chrome.storage.local.get(['sitesentinel_domain_warnings'], (result) => {
      const warnings = result.sitesentinel_domain_warnings || {};
      const stored = warnings[domain];
      if (stored && stored.verdict !== 'safe') {
        const threatScore = stored.threatScore || (100 - stored.score);
        if (threatScore >= 50) {
          chrome.action.setBadgeText({ tabId, text: '!' });
          chrome.action.setBadgeBackgroundColor({ tabId, color: '#dc2626' });
        } else {
          chrome.action.setBadgeText({ tabId, text: '?' });
          chrome.action.setBadgeBackgroundColor({ tabId, color: '#d97706' });
        }
      }
    });
  } catch (e) {}
}

// Clean up telemetry when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabTelemetry[tabId];
});

// Reset telemetry and check URL when navigation starts
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    tabTelemetry[tabId] = {
      thirdPartyRequests: 0,
      thirdPartyDomains: new Set(),
      domainCategories: {},
      trackingScripts: 0,
      analyticsScripts: 0,
      adScripts: 0
    };
  }

  if (changeInfo.status === 'complete' && tab.url) {
    updateBadgeForTab(tabId, tab.url);
    checkStoredWarning(tabId, tab.url);
  }
});

function initTabTelemetry(tabId) {
  if (!tabTelemetry[tabId]) {
    tabTelemetry[tabId] = {
      thirdPartyRequests: 0,
      thirdPartyDomains: new Set(),
      domainCategories: {},
      trackingScripts: 0,
      analyticsScripts: 0,
      adScripts: 0
    };
  }
}

// Intercept network requests
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0) return;

    initTabTelemetry(tabId);

    if (details.initiator) {
      try {
        const initiatorUrl = new URL(details.initiator);
        const requestUrl = new URL(details.url);

        if (requestUrl.hostname !== initiatorUrl.hostname) {
          const telem = tabTelemetry[tabId];
          telem.thirdPartyRequests++;
          telem.thirdPartyDomains.add(requestUrl.hostname);

          const path = requestUrl.pathname.toLowerCase() + requestUrl.search.toLowerCase();
          const host = requestUrl.hostname.toLowerCase();
          const fullUrl = details.url.toLowerCase();
          const dom = requestUrl.hostname.toLowerCase();

          const isAnalytics = host.includes('analytics') || host.includes('stat') || path.includes('telemetry') || path.includes('metrics') || fullUrl.includes('gtag') || fullUrl.includes('mixpanel') || fullUrl.includes('amplitude');
          const isAd = host.includes('doubleclick') || host.includes('adsense') || host.includes('adsystem') || host.includes('pixel') || host.includes('adserver') || fullUrl.includes('fbevents') || fullUrl.includes('facebook.com/tr');
          const isTracking = host.includes('track') || path.includes('beacon') || path.includes('logger') || fullUrl.includes('collect');

          let category = 'other';
          if (isAnalytics) {
            telem.analyticsScripts++;
            category = 'analytics';
          } else if (isAd) {
            telem.adScripts++;
            category = 'advertising';
          } else if (isTracking) {
            telem.trackingScripts++;
            category = 'tracking';
          }

          if (!telem.domainCategories[dom]) {
            telem.domainCategories[dom] = { count: 0, categories: {} };
          }
          telem.domainCategories[dom].count++;
          telem.domainCategories[dom].categories[category] = (telem.domainCategories[dom].categories[category] || 0) + 1;
        }
      } catch (e) {}
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['sitesentinel_settings'], (result) => {
    if (!result.sitesentinel_settings) {
      chrome.storage.local.set({
        sitesentinel_settings: {
          realtime: true,
          email: true,
          notifications: false,
          dataCollection: true,
          whitelist: [],
          downloadProtection: true
        }
      });
    }
  });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'get_network_telemetry') {
    const tabId = msg.tabId;
    const telem = tabTelemetry[tabId] || {
      thirdPartyRequests: 0,
      thirdPartyDomains: new Set(),
      domainCategories: {},
      trackingScripts: 0,
      analyticsScripts: 0,
      adScripts: 0
    };

    const domainArray = Array.from(telem.thirdPartyDomains).slice(0, 40);

    // Group domains by main domain for subdomain breakdown
    const domainGroups = {};
    domainArray.forEach(dom => {
      const main = getMainDomain(dom);
      const sub = dom === main ? 'www' : dom.slice(0, -(main.length + 1));
      const info = telem.domainCategories[dom] || { count: 0, categories: { other: 0 } };
      if (!domainGroups[main]) domainGroups[main] = { subdomains: {}, total: 0 };
      domainGroups[main].subdomains[sub] = { count: info.count, categories: info.categories };
      domainGroups[main].total += info.count;
    });

    sendResponse({
      thirdPartyRequests: telem.thirdPartyRequests,
      thirdPartyDomainsCount: telem.thirdPartyDomains.size,
      thirdPartyDomains: domainArray,
      domainGroups: domainGroups,
      trackingScripts: telem.trackingScripts,
      analyticsScripts: telem.analyticsScripts,
      adScripts: telem.adScripts
    });
    return true;
  }

  if (msg.action === 'capture_screenshot') {
    chrome.tabs.captureVisibleTab(msg.windowId || null, { format: 'png' }, (dataUrl) => {
      if (chrome.runtime.lastError) {
        sendResponse({ error: chrome.runtime.lastError.message });
        return;
      }
      sendResponse({ screenshot: dataUrl });
    });
    return true;
  }

  if (msg.action === 'check_url_phishing') {
    const result = checkUrlPhishingRisk(msg.url);
    sendResponse(result);
    return true;
  }

  if (msg.action === 'set_badge') {
    chrome.action.setBadgeText({ tabId: msg.tabId, text: msg.text || '' });
    if (msg.color) {
      chrome.action.setBadgeBackgroundColor({ tabId: msg.tabId, color: msg.color });
    }
    sendResponse({ ok: true });
    return true;
  }

  if (msg.action === 'get_download_protection_stats') {
    sendResponse({ stats: downloadStats });
    return true;
  }

  if (msg.action === 'set_download_protection') {
    chrome.storage.local.get(['sitesentinel_settings'], (result) => {
      const settings = result.sitesentinel_settings || {};
      settings.downloadProtection = msg.enabled;
      chrome.storage.local.set({ sitesentinel_settings: settings }, () => {
        sendResponse({ ok: true });
      });
    });
    return true;
  }
});

// Keyboard shortcut: Ctrl+Shift+S to scan
chrome.commands.onCommand.addListener((command) => {
  if (command === 'trigger-scan') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs.length > 0) {
        chrome.action.openPopup();
      }
    });
  }
});

// Download Protection: intercept and scan file downloads
chrome.downloads.onCreated.addListener((downloadItem) => {
  chrome.storage.local.get(['sitesentinel_settings'], (result) => {
    const settings = result.sitesentinel_settings || {};
    if (settings.downloadProtection === false) return;
    if (!downloadItem || downloadItem.id == null) return;
    if (downloadItem.url && downloadItem.url.startsWith('blob:')) {
      // blob: URLs can still carry malware via "Save As" — check filename extension only
      const blobCheck = checkDownloadRisk(downloadItem);
      if (blobCheck.score >= 8) {
        chrome.downloads.cancel(downloadItem.id, () => {
          if (!chrome.runtime.lastError) {
            downloadStats.totalBlocked++;
            downloadStats.recentBlocks.unshift({
              url: downloadItem.url,
              filename: downloadItem.filename || 'unknown',
              score: blobCheck.score,
              reasons: blobCheck.reasons,
              time: Date.now()
            });
            if (downloadStats.recentBlocks.length > 20) downloadStats.recentBlocks.pop();
            try { var d2 = new URL(downloadItem.url).hostname; } catch(e) { var d2 = 'unknown'; }
            chrome.notifications.create({
              type: 'basic',
              iconUrl: 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'),
              title: 'Download Blocked',
              message: 'Site Sentinel blocked a risky blob download (' + blobCheck.reasons.slice(0, 2).join(', ') + ')',
              priority: 2
            });
          }
        });
      }
      return;
    }

    const result2 = checkDownloadRisk(downloadItem);
    const score = result2.score;
    const reasons = result2.reasons;

    if (score >= 8) {
      chrome.downloads.cancel(downloadItem.id, () => {
        if (!chrome.runtime.lastError) {
          downloadStats.totalBlocked++;
          downloadStats.recentBlocks.unshift({
            url: downloadItem.url,
            filename: downloadItem.filename || 'unknown',
            score: score,
            reasons: reasons,
            time: Date.now()
          });
          if (downloadStats.recentBlocks.length > 20) downloadStats.recentBlocks.pop();
          const domain = (() => { try { return new URL(downloadItem.url).hostname; } catch (e) { return 'unknown'; } })();
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'),
            title: 'Download Blocked',
            message: 'Site Sentinel blocked a risky download from ' + domain + ' (' + reasons.slice(0, 2).join(', ') + ')',
            priority: 2
          });
        }
      });
    } else if (score >= 5) {
      downloadStats.totalWarned++;
      const domain = (() => { try { return new URL(downloadItem.url).hostname; } catch (e) { return 'unknown'; } })();
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'),
        title: 'Suspicious Download',
        message: 'Site Sentinel detected a suspicious file from ' + domain + ' (' + reasons.slice(0, 2).join(', ') + ')',
        priority: 1
      });
    }
  });
});
