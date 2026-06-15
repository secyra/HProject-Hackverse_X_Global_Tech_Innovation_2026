function getMainDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  const twoPartTlds = ['co.uk','co.jp','com.au','co.nz','co.in','co.za','com.br','org.uk','ac.uk','gov.uk','net.au','org.au'];
  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTlds.includes(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function getUrlPurpose(url) {
  const u = url.toLowerCase();
  if (u.includes('/login')||u.includes('/signin')||u.includes('/auth')||u.includes('/sso')) return 'login';
  if (u.includes('/checkout')||u.includes('/cart')||u.includes('/payment')||u.includes('/pay')||u.includes('/billing')) return 'payment';
  if (u.includes('/download')||u.includes('/dl/')||u.includes('/file/')||u.includes('/asset')) return 'download';
  if (u.includes('/api/')||u.includes('/v1/')||u.includes('/v2/')||u.includes('/v3/')||u.includes('/graphql')||u.includes('/rest/')) return 'api';
  if (u.includes('cdn')||u.includes('static')||u.includes('assets')||u.includes('/img/')||u.includes('/css/')||u.includes('/js/')||u.includes('/font/')) return 'cdn';
  if (u.includes('facebook')||u.includes('twitter')||u.includes('instagram')||u.includes('linkedin')||u.includes('youtube')||u.includes('tiktok')||u.includes('pinterest')) return 'social';
  if (u.includes('google-analytics')||u.includes('gtag')||u.includes('analytics')||u.includes('mixpanel')||u.includes('amplitude')||u.includes('hotjar')) return 'analytics';
  if (u.includes('/ads/')||u.includes('doubleclick')||u.includes('adsense')||u.includes('adserver')||u.includes('pixel')) return 'advertising';
  return 'other';
}

const SUSPICIOUS_KEYWORDS = [
  { kw: "verify your account", category: "phishing", severity: 9 },
  { kw: "verify your identity", category: "phishing", severity: 9 },
  { kw: "confirm your account", category: "phishing", severity: 8 },
  { kw: "confirm your identity", category: "phishing", severity: 9 },
  { kw: "account verification required", category: "phishing", severity: 8 },
  { kw: "sign in to verify", category: "phishing", severity: 7 },
  { kw: "your account has been locked", category: "phishing", severity: 9 },
  { kw: "your account has been suspended", category: "phishing", severity: 9 },
  { kw: "your account has been compromised", category: "phishing", severity: 10 },
  { kw: "your account will be closed", category: "phishing", severity: 8 },
  { kw: "your account will be terminated", category: "phishing", severity: 8 },
  { kw: "suspension notice", category: "phishing", severity: 8 },
  { kw: "account disabled", category: "phishing", severity: 8 },
  { kw: "reactivate your account", category: "phishing", severity: 7 },

  { kw: "urgent action required", category: "urgency", severity: 9 },
  { kw: "urgent security notice", category: "urgency", severity: 9 },
  { kw: "immediate action required", category: "urgency", severity: 8 },
  { kw: "response required within", category: "urgency", severity: 7 },
  { kw: "act now", category: "urgency", severity: 5 },
  { kw: "act immediately", category: "urgency", severity: 6 },
  { kw: "do not delay", category: "urgency", severity: 5 },
  { kw: "limited time", category: "urgency", severity: 4 },
  { kw: "expires today", category: "urgency", severity: 5 },
  { kw: "offer expires", category: "urgency", severity: 4 },
  { kw: "last chance", category: "urgency", severity: 4 },

  { kw: "update password", category: "credential_theft", severity: 8 },
  { kw: "change your password", category: "credential_theft", severity: 7 },
  { kw: "reset your password", category: "credential_theft", severity: 7 },
  { kw: "password expired", category: "credential_theft", severity: 7 },
  { kw: "re-enter your password", category: "credential_theft", severity: 7 },
  { kw: "your password has expired", category: "credential_theft", severity: 7 },
  { kw: "update billing information", category: "credential_theft", severity: 8 },
  { kw: "confirm your password", category: "credential_theft", severity: 7 },
  { kw: "enter your login", category: "credential_theft", severity: 6 },

  { kw: "security alert", category: "social_engineering", severity: 8 },
  { kw: "security notification", category: "social_engineering", severity: 6 },
  { kw: "unusual sign-in attempt", category: "social_engineering", severity: 9 },
  { kw: "suspicious activity detected", category: "social_engineering", severity: 9 },
  { kw: "someone tried to access", category: "social_engineering", severity: 9 },
  { kw: "new device detected", category: "social_engineering", severity: 7 },
  { kw: "unusual login detected", category: "social_engineering", severity: 9 },
  { kw: "new login from", category: "social_engineering", severity: 7 },
  { kw: "we detected unusual activity", category: "social_engineering", severity: 8 },

  { kw: "congratulations you won", category: "scam", severity: 8 },
  { kw: "you have been selected", category: "scam", severity: 7 },
  { kw: "you are a winner", category: "scam", severity: 8 },
  { kw: "claim your prize", category: "scam", severity: 8 },
  { kw: "claim your reward", category: "scam", severity: 7 },
  { kw: "gift card winner", category: "scam", severity: 9 },
  { kw: "you won a prize", category: "scam", severity: 8 },
  { kw: "lottery winner", category: "scam", severity: 9 },
  { kw: "exclusive deal", category: "scam", severity: 4 },
  { kw: "risk of closure", category: "scam", severity: 7 },
  { kw: "limited offer", category: "scam", severity: 3 },

  { kw: "exclusive opportunity", category: "scam", severity: 5 },
  { kw: "free gift", category: "scam", severity: 4 },
  { kw: "cash reward", category: "scam", severity: 7 },
  { kw: "inheritance", category: "scam", severity: 9 },
  { kw: "wire transfer", category: "scam", severity: 8 },
  { kw: "western union", category: "scam", severity: 8 },
  { kw: "money gram", category: "scam", severity: 8 },
  { kw: "bank transfer", category: "scam", severity: 5 },

  { kw: "malware detected", category: "malware", severity: 10 },
  { kw: "virus detected", category: "malware", severity: 10 },
  { kw: "your computer is infected", category: "malware", severity: 10 },
  { kw: "your system is compromised", category: "malware", severity: 10 },
  { kw: "scan your computer", category: "malware", severity: 8 },
  { kw: "remove virus", category: "malware", severity: 8 },
  { kw: "click here to remove", category: "malware", severity: 8 },
  { kw: "install security tool", category: "malware", severity: 7 },
  { kw: "dangerous virus", category: "malware", severity: 9 },
  { kw: "immediate security scan", category: "malware", severity: 8 },

  { kw: "billing update", category: "financial", severity: 6 },
  { kw: "payment failed", category: "financial", severity: 7 },
  { kw: "payment declined", category: "financial", severity: 7 },
  { kw: "credit card declined", category: "financial", severity: 8 },
  { kw: "refund available", category: "financial", severity: 5 },
  { kw: "tax refund", category: "financial", severity: 7 },
  { kw: "unusual transaction", category: "financial", severity: 8 },
  { kw: "unauthorized transaction", category: "financial", severity: 9 },
  { kw: "fraud alert", category: "financial", severity: 9 },
  { kw: "bank account update", category: "financial", severity: 7 }
];

const SUSPICIOUS_DOMAIN_PATTERNS = [
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
  /apple.*\.(?:xyz|top|club|gq|ml|tk|ga)/i,
  /google.*\.(?:xyz|top|club|gq|ml|tk|ga)/i,
  /facebook.*\.(?:xyz|top|club|gq|ml|tk|ga)/i,
  /microsoft.*\.(?:xyz|top|club|gq|ml|tk|ga)/i,
  /\b(?:secure|account|verify|signin|login|update|confirm)\b.*\.(?:xyz|top|club|gq|ml|tk|cf|ga)\b/i,
  /^\w{8,12}\.(?:xyz|top|club|gq|ml|tk|cf|ga)$/i,
  /(?:paypa1|paypaI|arnazon|arnaz0n|netf1ix|g00gle|faceb00k|micros0ft|app1e|whatsapp|instagrarn|rnitflix)/i
];

const KNOWN_PHISHING_KEYWORDS_IN_URL = [
  'login', 'signin', 'sign-in', 'account', 'verify', 'update', 'secure',
  'confirm', 'password', 'credential', 'banking', 'authenticate',
  'security', 'webscr', 'paypal', 'amazon', 'netflix', 'appleid',
  'resetpassword', 'forgotpassword', 'changepassword'
];

const LOW_CREDIBILITY_TLDS = [
  'xyz', 'top', 'club', 'gq', 'ml', 'tk', 'cf', 'ga', 'work',
  'review', 'loan', 'win', 'bid', 'trade', 'webcam', 'science',
  'party', 'racing', 'date', 'men', 'click', 'faith', 'moe',
  'download', 'stream', 'host', 'site', 'online', 'space', 'press'
];

async function checkPermissions() {
  const results = {};
  const permissionsList = ['geolocation', 'notifications', 'camera', 'microphone'];
  for (const name of permissionsList) {
    try {
      const status = await navigator.permissions.query({ name });
      results[name] = status.state;
    } catch (e) {
      results[name] = 'denied/unsupported';
    }
  }
  return results;
}

function classifyCookies() {
  let sessionCookies = 0;
  let persistentCookies = 0;
  let thirdPartyCookies = 0;
  const cookies = document.cookie.split(';').filter(c => c.trim());
  cookies.forEach(c => {
    const parts = c.trim().split('=');
    if (parts.length >= 1) {
      sessionCookies++;
    }
  });
  return { total: cookies.length, session: sessionCookies };
}

function analyzeSecurityMeta() {
  let hasCSP = false;
  let hasXFrame = false;
  let hasXSS = false;
  const metas = document.querySelectorAll('meta');
  metas.forEach(m => {
    const httpEquiv = (m.getAttribute('http-equiv') || '').toLowerCase();
    const content = (m.getAttribute('content') || '').toLowerCase();
    if (httpEquiv === 'content-security-policy' || httpEquiv === 'csp') {
      hasCSP = true;
    }
    if (httpEquiv === 'x-frame-options') {
      hasXFrame = true;
    }
    if (httpEquiv === 'x-xss-protection') {
      hasXSS = true;
    }
  });

  const frameAncestors = document.querySelectorAll('meta[http-equiv="content-security-policy"]');
  frameAncestors.forEach(m => {
    const c = m.getAttribute('content') || '';
    if (c.toLowerCase().includes('frame-ancestors')) {
      hasCSP = true;
    }
  });

  return { hasCSP, hasXFrame, hasXSS };
}

function analyzeHiddenElements() {
  let hiddenIframes = 0;
  let tinyIframes = 0;
  let hiddenInputs = 0;
  let invisibleElements = 0;

  document.querySelectorAll('iframe').forEach(f => {
    const w = parseInt(f.getAttribute('width') || f.style.width || '0');
    const h = parseInt(f.getAttribute('height') || f.style.height || '0');
    if (w === 0 || h === 0 || (w < 5 && h < 5)) {
      tinyIframes++;
    }
    if (f.hidden || f.style.display === 'none' || f.style.visibility === 'hidden') {
      hiddenIframes++;
    }
  });

  document.querySelectorAll('input[type="hidden"]').forEach(() => {
    hiddenInputs++;
  });

  document.querySelectorAll('*').forEach(el => {
    const style = window.getComputedStyle(el);
    if (el.offsetWidth === 0 && el.offsetHeight === 0 && el.children.length === 0) return;
    if (style.display === 'none' && el.children.length > 0 && el.textContent.trim().length > 50) {
      invisibleElements++;
    }
  });

  return { hiddenIframes, tinyIframes, hiddenInputs, invisibleElements };
}

function detectTechStack() {
  const tech = [];
  const html = document.documentElement.innerHTML.toLowerCase();

  if (document.querySelector('meta[name="generator"][content*="WordPress"]') || html.includes('wp-content') || html.includes('/wp-json/')) tech.push('WordPress');
  if (html.includes('cdn.shopify.com') || document.querySelector('meta[name="shopify"') || html.includes('shopify')) tech.push('Shopify');
  if (document.querySelector('meta[name="generator"][content*="Drupal"]') || html.includes('drupal')) tech.push('Drupal');
  if (document.querySelector('meta[name="generator"][content*="Joomla"]') || html.includes('joomla')) tech.push('Joomla');
  if (html.includes('react') || html.includes('reactroot') || html.includes('react-dom')) tech.push('React');
  if (html.includes('vue') || html.includes('vue.js') || document.querySelector('#app, [data-v-')) tech.push('Vue.js');
  if (html.includes('angular') || document.querySelector('[ng-app], [ng-controller]')) tech.push('Angular');
  if (html.includes('jquery')) tech.push('jQuery');
  if (html.includes('bootstrap')) tech.push('Bootstrap');
  if (html.includes('tailwind')) tech.push('Tailwind CSS');
  if (html.includes('google-analytics') || html.includes('ga(') || html.includes('gtag(')) tech.push('Google Analytics');
  if (html.includes('facebook.com/tr') || html.includes('fbq(')) tech.push('Facebook Pixel');
  if (html.includes('cloudflare')) tech.push('Cloudflare');

  return tech;
}

async function runAnalysis() {
  const forms = document.querySelectorAll('form');
  let loginForms = 0;
  let paymentForms = 0;
  let externalFormActions = 0;
  const formActions = [];
  const suspiciousFormActions = [];
  const formActionHosts = [];

  forms.forEach(form => {
    const action = form.getAttribute('action') || '';
    let absoluteAction = '';
    try {
      absoluteAction = new URL(action, window.location.href).href;
    } catch (e) {
      absoluteAction = action;
    }
    formActions.push(absoluteAction);

    try {
      const actionUrl = new URL(absoluteAction);
      if (actionUrl.hostname !== window.location.hostname) {
        externalFormActions++;
        formActionHosts.push(actionUrl.hostname);

        if (KNOWN_PHISHING_KEYWORDS_IN_URL.some(kw => actionUrl.pathname.toLowerCase().includes(kw))) {
          suspiciousFormActions.push(absoluteAction);
        }
      }
    } catch (e) {}

    const hasPassword = form.querySelector('input[type="password"]') !== null;
    const formText = form.innerText.toLowerCase();
    if (hasPassword || formText.includes('log in') || formText.includes('login') || formText.includes('sign in')) {
      loginForms++;
    }
    if (formText.includes('payment') || formText.includes('credit card') || formText.includes('checkout') || formText.includes('pay now')) {
      paymentForms++;
    }
  });

  const passwordFields = document.querySelectorAll('input[type="password"]').length;

  const inputs = document.querySelectorAll('input, textarea, select');
  let nameFields = 0;
  let emailFields = 0;
  let phoneFields = 0;
  let addressFields = 0;
  let dobFields = 0;
  let creditCardFields = 0;
  let fileUploadFields = 0;

  inputs.forEach(input => {
    const type = (input.getAttribute('type') || '').toLowerCase();
    const name = (input.getAttribute('name') || '').toLowerCase();
    const id = (input.getAttribute('id') || '').toLowerCase();
    const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();

    const matchText = `${name} ${id} ${placeholder} ${autocomplete} ${ariaLabel}`;

    if (type === 'file') {
      fileUploadFields++;
      return;
    }

    if (
      matchText.includes('card') || 
      matchText.includes('cc') || 
      matchText.includes('cvv') || 
      matchText.includes('cvc') || 
      matchText.includes('expiry') ||
      type === 'cc-number'
    ) {
      creditCardFields++;
      return;
    }

    if (type === 'email' || matchText.includes('email') || matchText.includes('mail')) {
      emailFields++;
      return;
    }

    if (type === 'tel' || matchText.includes('phone') || matchText.includes('tel') || matchText.includes('mobile')) {
      phoneFields++;
      return;
    }

    if (matchText.includes('dob') || matchText.includes('birth') || matchText.includes('bday')) {
      dobFields++;
      return;
    }

    if (
      matchText.includes('address') || 
      matchText.includes('street') || 
      matchText.includes('zip') || 
      matchText.includes('postcode') || 
      matchText.includes('city') || 
      matchText.includes('state') || 
      matchText.includes('country')
    ) {
      addressFields++;
      return;
    }

    if (
      matchText.includes('name') && 
      !matchText.includes('username') && 
      !matchText.includes('cardname')
    ) {
      nameFields++;
      return;
    }
  });

  const bodyText = document.body ? document.body.innerText.toLowerCase() : "";

  const detectedKeywordEntries = [];
  SUSPICIOUS_KEYWORDS.forEach(entry => {
    if (bodyText.includes(entry.kw)) {
      detectedKeywordEntries.push(entry);
    }
  });

  const detectedCategories = {};
  detectedKeywordEntries.forEach(entry => {
    if (!detectedCategories[entry.category]) {
      detectedCategories[entry.category] = { count: 0, maxSeverity: 0, keywords: [] };
    }
    detectedCategories[entry.category].count++;
    detectedCategories[entry.category].maxSeverity = Math.max(detectedCategories[entry.category].maxSeverity, entry.severity);
    detectedCategories[entry.category].keywords.push(entry.kw);
  });

  const linkNodes = document.querySelectorAll('a[href]');
  let internalLinks = 0;
  let externalLinks = 0;
  let shortenedUrls = 0;
  let hasPrivacyPolicy = false;
  let hasTerms = false;
  let hasContact = false;
  const externalLinkUrls = [];
  const externalLinkDetails = {};
  const suspiciousExternalLinks = [];
  const lowCredibilityLinks = [];
  const suspiciousLinkDomains = [];

  const shorteners = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'rebrand.ly', 
    'is.gd', 'buff.ly', 'adf.ly', 'ow.ly', 'mcaf.ee', 'su.pr',
    'shorturl.at', 'cutt.ly', 'shorte.st', 'tiny.cc', 'tr.im',
    'v.gd', 'cli.gs', 'u.nu', 'snipurl.com', 'snurl.com',
    'shorturl.com', 'notlong.com', 'moourl.com'
  ];

  linkNodes.forEach(link => {
    const href = link.getAttribute('href') || '';
    const text = (link.textContent || '').toLowerCase();
    const hrefLower = href.toLowerCase();

    if (text.includes('privacy') || hrefLower.includes('privacy')) {
      hasPrivacyPolicy = true;
    }
    if (text.includes('terms') || text.includes('condition') || hrefLower.includes('terms') || hrefLower.includes('condition')) {
      hasTerms = true;
    }
    if (text.includes('contact') || hrefLower.includes('contact') || text.includes('support') || hrefLower.includes('support')) {
      hasContact = true;
    }

    let absoluteUrl = '';
    try {
      absoluteUrl = new URL(href, window.location.href).href;
    } catch (e) {
      return;
    }

    try {
      const urlObj = new URL(absoluteUrl);
      const isShortener = shorteners.some(s => urlObj.hostname === s || urlObj.hostname.endsWith('.' + s));
      if (isShortener) {
        shortenedUrls++;
      }

      if (urlObj.hostname === window.location.hostname) {
        internalLinks++;
      } else {
        externalLinks++;
        if (externalLinkUrls.length < 30) {
          externalLinkUrls.push(absoluteUrl);
          const hostLow = urlObj.hostname.toLowerCase();
          const mainDomain = getMainDomain(hostLow);
          const subdomain = hostLow === mainDomain ? 'www' : hostLow.slice(0, -(mainDomain.length + 1));
          const purpose = getUrlPurpose(absoluteUrl);
          if (!externalLinkDetails[mainDomain]) {
            externalLinkDetails[mainDomain] = { subdomains: {}, purposes: {}, urls: [] };
          }
          externalLinkDetails[mainDomain].subdomains[subdomain] = (externalLinkDetails[mainDomain].subdomains[subdomain] || 0) + 1;
          externalLinkDetails[mainDomain].purposes[purpose] = (externalLinkDetails[mainDomain].purposes[purpose] || 0) + 1;
          externalLinkDetails[mainDomain].urls.push({ url: absoluteUrl, subdomain, purpose });
        }

        const hostname = urlObj.hostname.toLowerCase();
        const fullUrl = absoluteUrl.toLowerCase();

        const isSuspicious = SUSPICIOUS_DOMAIN_PATTERNS.some(pattern => pattern.test(hostname) || pattern.test(fullUrl));
        if (isSuspicious && suspiciousExternalLinks.length < 20) {
          suspiciousExternalLinks.push(absoluteUrl);
          suspiciousLinkDomains.push(hostname);
        }

        const tld = hostname.split('.').pop();
        if (LOW_CREDIBILITY_TLDS.includes(tld) && lowCredibilityLinks.length < 20) {
          lowCredibilityLinks.push(absoluteUrl);
        }
      }
    } catch (e) {}
  });

  const iframes = document.querySelectorAll('iframe').length;

  const permissions = await checkPermissions();
  const isHttps = window.location.protocol === 'https:';
  const scripts = document.querySelectorAll('script').length;
  const metaTags = document.querySelectorAll('meta').length;


  const cookieInfo = classifyCookies();
  const securityMeta = analyzeSecurityMeta();
  const hiddenElements = analyzeHiddenElements();
  const techStack = detectTechStack();

  return {
    url: window.location.href,
    domain: window.location.hostname,
    title: document.title,
    formCount: forms.length,
    loginForms,
    paymentForms,
    passwordFields,
    externalFormActions,
    suspiciousFormActions,
    formActionHosts,
    detectedKeywords: detectedKeywordEntries.map(e => e.kw),
    keywordCategories: detectedCategories,
    keywordTotalSeverity: detectedKeywordEntries.reduce((sum, e) => sum + e.severity, 0),
    iframes,
    scriptCount: scripts,
    metaCount: metaTags,
    dataFields: {
      nameFields,
      emailFields,
      phoneFields,
      addressFields,
      dobFields,
      creditCardFields,
      fileUploadFields
    },
    links: {
      internalLinks,
      externalLinks,
      shortenedUrls,
      totalLinks: linkNodes.length,
      externalLinkUrls,
      externalLinkDetails,
      suspiciousExternalLinks,
      suspiciousLinkDomains,
      lowCredibilityLinks
    },
    trust: {
      isHttps,
      hasPrivacyPolicy,
      hasTerms,
      hasContact,
      cookieCount: cookieInfo.total,
      sessionCookies: cookieInfo.session
    },
    permissions,
    security: {
      hasCSP: securityMeta.hasCSP,
      hasXFrameOptions: securityMeta.hasXFrame,
      hasXSSProtection: securityMeta.hasXSS
    },
    hiddenElements,
    techStack,
    threatCategories: Object.keys(detectedCategories)
  };
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "get_telemetry") {
    runAnalysis().then(telemetry => {
      sendResponse(telemetry);
    });
    return true;
  }
});
