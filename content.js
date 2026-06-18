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
  let credentialFormFound = false;
  let credentialFormSecure = true;

  inputs.forEach(input => {
    const tagName = input.tagName.toLowerCase();
    const type = (input.getAttribute('type') || '').toLowerCase();
    const name = (input.getAttribute('name') || '').toLowerCase();
    const iid = (input.getAttribute('id') || '').toLowerCase();
    const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
    const inputmode = (input.getAttribute('inputmode') || '').toLowerCase();
    const maxlength = parseInt(input.getAttribute('maxlength') || '0');

    // Read associated label text (framework-proof — browser resolves labels natively)
    let labelText = '';
    const labels = input.labels || [];
    for (const lbl of labels) {
      labelText += ' ' + (lbl.textContent || '').toLowerCase();
    }

    // Walk up DOM for nearest heading/legend context
    let headingText = '';
    let el = input.parentElement;
    let depth = 0;
    while (el && el !== document.body && depth < 6) {
      const heading = el.querySelector(':scope > h1, :scope > h2, :scope > h3, :scope > h4, :scope > h5, :scope > h6, :scope > legend');
      if (heading) { headingText = (heading.textContent || '').toLowerCase(); break; }
      el = el.parentElement;
      depth++;
    }

    // Submit button text from parent form
    let submitText = '';
    const parentForm = input.closest('form');
    if (parentForm) {
      const submitBtn = parentForm.querySelector('button[type="submit"], input[type="submit"]');
      if (submitBtn) {
        submitText = (submitBtn.textContent || submitBtn.value || '').toLowerCase();
      }
    }

    // Prioritize autocomplete, label text, and inputmode over name/id
    const matchText = `${autocomplete} ${labelText} ${headingText} ${submitText} ${inputmode} ${ariaLabel} ${placeholder} ${name} ${iid}`;

    if (type === 'file') {
      fileUploadFields++;
      return;
    }

    // Credit card: autocomplete values, type, keywords, or inputmode+numeric+maxlength heuristic
    if (
      autocomplete === 'cc-number' || autocomplete === 'cc-name' ||
      autocomplete === 'cc-exp' || autocomplete === 'cc-csc' ||
      type === 'cc-number' ||
      /\b(card|cc|cvv|cvc|expiry|credit.?card)\b/.test(matchText) ||
      (inputmode === 'numeric' && maxlength >= 13 && maxlength <= 19)
    ) {
      creditCardFields++;
      return;
    }

    // Email
    if (type === 'email' || autocomplete === 'email' || inputmode === 'email' || /\b(email|e-mail)\b/.test(matchText)) {
      emailFields++;
      return;
    }

    // Phone
    if (type === 'tel' || autocomplete === 'tel' || inputmode === 'tel' || /\b(phone|mobile|cell|telephone|tel)\b/.test(matchText)) {
      phoneFields++;
      return;
    }

    // Date of birth
    if (autocomplete === 'bday' || /\b(dob|birth|bday)\b/.test(matchText)) {
      dobFields++;
      return;
    }

    // Address
    if (
      autocomplete.startsWith('address') || autocomplete === 'street-address' ||
      autocomplete === 'postal-code' || autocomplete === 'country-name' ||
      /\b(address|street|zip|postcode|postal|city|state|country)\b/.test(matchText)
    ) {
      addressFields++;
      return;
    }

    // Name
    if (
      autocomplete === 'name' || autocomplete === 'given-name' ||
      autocomplete === 'family-name' || autocomplete === 'full-name' ||
      (/\bname\b/.test(matchText) && !/\b(username|cardname)\b/.test(matchText))
    ) {
      nameFields++;
      return;
    }

    // Detect credential form by password field, autocomplete, or submit button text
    if (
      type === 'password' ||
      autocomplete === 'current-password' || autocomplete === 'new-password' ||
      /sign in|log in|sign up|register|create account|pay now|checkout|continue/.test(submitText)
    ) {
      credentialFormFound = true;
      if (!window.location.protocol.startsWith('https:')) {
        credentialFormSecure = false;
      }
    }
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
    credentialFormFound,
    credentialFormSecure,
    externalFormActions,
    suspiciousFormActions,
    formActionHosts,
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
    techStack
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
