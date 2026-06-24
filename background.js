try { importScripts('shield-domains.js'); } catch (e) { console.warn('[Shield] Failed to load shield-domains:', e); }

const tabTelemetry = {};

const SHIELD_RULE_PRIORITY = 1;
const SHIELD_RULE_ID_OFFSET = 1000;
let shieldEnabled = true;
let blockedCounts = {};
let aiClassifiedDomains = {};

function initShieldRules() {
  chrome.storage.local.get(['shieldEnabled'], (result) => {
    shieldEnabled = result.shieldEnabled !== false;
    if (shieldEnabled) {
      installShieldRules();
    }
  });
}

async function installShieldRules() {
  if (typeof TRACKER_DOMAINS === 'undefined' || !Array.isArray(TRACKER_DOMAINS)) {
    console.warn('[Shield] TRACKER_DOMAINS not available, skipping DNR rules');
    return;
  }
  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const existingIds = existingRules.map(r => r.id);
    const rules = TRACKER_DOMAINS.map((domain, i) => ({
      id: SHIELD_RULE_ID_OFFSET + i,
      priority: SHIELD_RULE_PRIORITY,
      action: { type: 'block' },
      condition: {
        urlFilter: '||' + domain + '^',
        resourceTypes: [
          'script', 'image', 'stylesheet', 'xmlhttprequest',
          'sub_frame', 'media', 'font', 'websocket', 'other'
        ]
      }
    }));
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingIds,
      addRules: rules
    });
    console.log('[Shield] Installed ' + rules.length + ' DNR block rules');
  } catch (e) {
    console.warn('[Shield] Failed to install DNR rules:', e);
  }
}

async function removeShieldRules() {
  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const ids = existingRules.filter(r => r.id >= SHIELD_RULE_ID_OFFSET).map(r => r.id);
    if (ids.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ids });
    }
    console.log('[Shield] Removed ' + ids.length + ' DNR block rules');
  } catch (e) {
    console.warn('[Shield] Failed to remove DNR rules:', e);
  }
}

async function aiClassifyDomain(domain) {
  if (aiClassifiedDomains[domain]) return aiClassifiedDomains[domain];
  try {
    const res = await fetch('http://127.0.0.1:8000/classify-domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    if (!res.ok) return null;
    const data = await res.json();
    aiClassifiedDomains[domain] = data;
    setTimeout(() => { delete aiClassifiedDomains[domain]; }, 3600000);
    return data;
  } catch (e) {
    return null;
  }
}

async function blockDomainViaAI(domain, tabId) {
  if (!shieldEnabled) return;
  const result = await aiClassifyDomain(domain);
  if (!result || !result.should_block) return;
  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const maxExistingId = existingRules.reduce((max, r) => Math.max(max, r.id), SHIELD_RULE_ID_OFFSET);
    const newRule = {
      id: maxExistingId + 1,
      priority: SHIELD_RULE_PRIORITY + 1,
      action: { type: 'block' },
      condition: {
        urlFilter: '||' + domain + '^',
        resourceTypes: ['script', 'image', 'xmlhttprequest', 'sub_frame', 'other']
      }
    };
    await chrome.declarativeNetRequest.updateDynamicRules({ addRules: [newRule] });
    if (tabId && tabId > 0) {
      blockedCounts[tabId] = (blockedCounts[tabId] || 0) + 1;
    }
    console.log('[Shield] AI blocked domain:', domain, '-', result.reason);
  } catch (e) {
    console.warn('[Shield] AI block failed for', domain, ':', e);
  }
}

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
      const defaults = { realtime: true, email: true, whitelist: [] };
      resolve({ ...defaults, ...result.sitesentinel_settings });
    });
  });
}

function isWhitelisted(domain, settings) {
  const whitelist = settings.whitelist || [];
  return whitelist.some(w => domain === w || domain.endsWith('.' + w));
}

function checkAndWarn(tabId, url) {
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;
  loadSettings().then(settings => {
    if (settings.realtime === false) return;
    try {
      const domain = new URL(url).hostname;
      if (isWhitelisted(domain, settings)) return;
      chrome.storage.session.get(['silencedUrls'], (result) => {
        const silenced = result.silencedUrls || {};
        const origin = (() => { try { return new URL(url).origin; } catch (_) { return null; } })();
        const isSilenced = origin && Object.keys(silenced).some(silencedUrl => {
          try { return new URL(silencedUrl).origin === origin; } catch (_) { return false; }
        });
        if (isSilenced) return;
        const riskResult = checkUrlPhishingRisk(url);
        if (riskResult.risk !== 'none') {
          chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL('warning.html') +
              '?target=' + encodeURIComponent(url) +
              '&risk=' + riskResult.risk +
              '&reason=' + encodeURIComponent(riskResult.reason)
          }, () => {});
        }
      });
    } catch (e) {}
  });
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

// Track DNR blocked requests for shield stats
if (chrome.declarativeNetRequest && chrome.declarativeNetRequest.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request.tabId;
    if (tabId > 0) {
      blockedCounts[tabId] = (blockedCounts[tabId] || 0) + 1;
      try {
        const url = new URL(info.request.url);
        chrome.runtime.sendMessage({
          action: 'shield_blocked',
          tabId,
          domain: url.hostname,
          url: info.request.url,
          ruleId: info.rule.ruleId
        }).catch(() => {});
      } catch (e) {}
    }
  });
}

// Clean up telemetry when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabTelemetry[tabId];
  delete blockedCounts[tabId];
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

    if (tab.url && !tab.url.startsWith('chrome-extension://')) {
      checkAndWarn(tabId, tab.url);
    }
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
  initShieldRules();
  chrome.storage.local.get(['sitesentinel_settings'], (result) => {
    if (!result.sitesentinel_settings) {
      chrome.storage.local.set({
        sitesentinel_settings: {
          realtime: true,
          email: true,
          whitelist: [],
        }
      });
    }
  });
});

chrome.runtime.onStartup.addListener(() => {
  initShieldRules();
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

  if (msg.action === 'silence_url_warning') {
    chrome.storage.session.get(['silencedUrls'], (result) => {
      const silenced = result.silencedUrls || {};
      silenced[msg.url] = Date.now();
      if (msg.dontWarn && msg.domain) {
        chrome.storage.local.get(['sitesentinel_settings'], (settingsResult) => {
          const settings = settingsResult.sitesentinel_settings || {};
          settings.whitelist = settings.whitelist || [];
          if (!settings.whitelist.includes(msg.domain)) {
            settings.whitelist.push(msg.domain);
            chrome.storage.local.set({ sitesentinel_settings: settings }, () => {
              chrome.storage.session.set({ silencedUrls: silenced }, () => {
                sendResponse({ ok: true });
              });
            });
          } else {
            chrome.storage.session.set({ silencedUrls: silenced }, () => {
              sendResponse({ ok: true });
            });
          }
        });
      } else {
        chrome.storage.session.set({ silencedUrls: silenced }, () => {
          sendResponse({ ok: true });
        });
      }
    });
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

  // Shield message handlers
  if (msg.action === 'get_shield_stats') {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      const tabId = tab ? tab.id : -1;
      sendResponse({
        enabled: shieldEnabled,
        blockedThisPage: blockedCounts[tabId] || 0,
        totalBlocked: Object.values(blockedCounts).reduce((a, b) => a + b, 0),
        rulesCount: TRACKER_DOMAINS.length
      });
    });
    return true;
  }

  if (msg.action === 'toggle_shield') {
    shieldEnabled = msg.enabled;
    chrome.storage.local.set({ shieldEnabled });
    if (shieldEnabled) {
      installShieldRules();
    } else {
      removeShieldRules();
    }
    sendResponse({ enabled: shieldEnabled });
    return true;
  }

  if (msg.action === 'ai_classify_domain') {
    aiClassifyDomain(msg.domain).then(result => {
      sendResponse(result || { should_block: false });
    });
    return true;
  }

  if (msg.action === 'check_and_block_third_party') {
    if (!shieldEnabled) { sendResponse({ blocked: false }); return true; }
    const domains = msg.domains || [];
    Promise.all(domains.map(d => blockDomainViaAI(d, msg.tabId))).then(() => {
      sendResponse({ blocked: true });
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


