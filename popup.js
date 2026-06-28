document.addEventListener('DOMContentLoaded', () => {
  let activeTabInfo = null;
  let activeTelemetry = null;
  let _lastNetworkData = null;
  let _lastRootDomain = '';
  let _lastVerdict = 'safe';

  initTabs();
  initSettings();
  loadHistory();

  // Show current domain on landing, and restore cached scan if available
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (!tab) return;
      activeTabInfo = tab;
      let domain = 'N/A';
      try { domain = new URL(tab.url).hostname; } catch (_) {}
      document.getElementById('landing-domain').textContent = domain;
      restoreCachedScan(domain);
    });
  }

  function restoreCachedScan(domain) {
    if (!chrome.storage || !chrome.storage.session) return;
    const key = 'sitesentinel_scan_' + domain;
    chrome.storage.session.get([key], (result) => {
      const cached = result[key];
      if (!cached || !cached.scanResult) {
        console.log('[SiteSentinel] No cached scan for', domain);
        return;
      }
      console.log('[SiteSentinel] Restoring cached scan for', domain);
      showResults(cached.scanResult, cached.telemetry || {}, cached.deepResult || null);
      if (domain && domain !== 'N/A') {
        fetchAndShowTrustProfile(domain);
      }
    });
  }

  // Scan Now button
  document.getElementById('btn-start-scan').addEventListener('click', startUnifiedScan);
  // Rescan button
  document.getElementById('btn-rescan').addEventListener('click', startUnifiedScan);

  // Wire up collapsible evidence sections
  document.querySelectorAll('.evidence-header').forEach(header => {
    header.addEventListener('click', () => {
      const targetId = header.getAttribute('data-target');
      const content = document.getElementById(targetId);
      const chevron = header.querySelector('.evidence-chevron');
      if (content) {
        content.classList.toggle('hidden');
        if (chevron) chevron.classList.toggle('open');
      }
    });
  });

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  async function startUnifiedScan() {
    console.log('[SiteSentinel] Scan Again clicked — starting fresh scan');
    if (!activeTabInfo) { console.log('[SiteSentinel] No active tab info, aborting'); return; }

    const overlay = document.getElementById('scan-loading-overlay');
    const loadingText = document.getElementById('loading-text');
    overlay.classList.remove('hidden');

    // Step 1: Collect DOM telemetry
    loadingText.textContent = 'Collecting page data...';
    let telemetry = await collectTelemetry();
    if (!telemetry) {
      telemetry = {
        url: activeTabInfo.url,
        domain: (() => { try { return new URL(activeTabInfo.url).hostname; } catch (e) { return 'N/A'; } })(),
        title: activeTabInfo.title,
        formCount: 0,
        trust: { isHttps: activeTabInfo.url.startsWith('https:') }
      };
    }
    activeTelemetry = telemetry;

    // Step 2: Collect network telemetry
    loadingText.textContent = 'Analyzing network requests...';
    const netTelemetry = await getNetworkTelemetry(activeTabInfo.id);
    if (netTelemetry) {
      telemetry.network = netTelemetry;
    }

    // Step 3: Send to backend for analysis
    loadingText.textContent = 'Running security analysis...';
    const scanResult = await analyzePage(telemetry);

    // Step 4: Run deep scan
    let deepResult = null;
    try {
      let settings = { deepScan: true };
      const stored = localStorage.getItem('sitesentinel_settings');
      if (stored) {
        settings = JSON.parse(stored);
      }
      if (settings.deepScan !== false && activeTabInfo.url) {
        loadingText.textContent = 'Crawling site pages...';
        deepResult = await runDeepScan(activeTabInfo.url);
      }
    } catch (_) {}

    overlay.classList.add('hidden');

    // Step 5: Show all results immediately
    showResults(scanResult, telemetry, deepResult);

    // Cache scan result so reopening popup on same page shows results immediately
    cacheScanResult(scanResult, telemetry, deepResult);

    // Step 6: Fetch trust profile separately (non-blocking) — fills in after results show
    const domain = telemetry.domain || scanResult.domain;
    if (domain && domain !== 'N/A') {
      fetchAndShowTrustProfile(domain);
    }
  }

  function cacheScanResult(scanResult, telemetry, deepResult) {
    if (!activeTabInfo || !activeTabInfo.url) return;
    let domain;
    try { domain = new URL(activeTabInfo.url).hostname; } catch (_) { return; }
    const key = 'sitesentinel_scan_' + domain;
    const data = { scanResult, telemetry, deepResult, domain, timestamp: Date.now() };
    try {
      chrome.storage.session.set({ [key]: data });
    } catch (_) {}
  }

  function collectTelemetry() {
    return new Promise((resolve) => {
      if (!activeTabInfo || !chrome.tabs || !chrome.tabs.sendMessage) {
        resolve(null);
        return;
      }
      chrome.tabs.sendMessage(activeTabInfo.id, { action: "get_telemetry" }, (response) => {
        if (chrome.runtime.lastError || !response) {
          resolve(null);
          return;
        }
        resolve(response);
      });
    });
  }

  function getNetworkTelemetry(tabId) {
    return new Promise((resolve) => {
      if (!chrome.runtime || !chrome.runtime.sendMessage) {
        resolve(null);
        return;
      }
      chrome.runtime.sendMessage({ action: "get_network_telemetry", tabId: tabId }, (resp) => {
        if (chrome.runtime.lastError || !resp) {
          resolve(null);
          return;
        }
        resolve(resp);
      });
    });
  }

  async function analyzePage(telemetry) {
    const payload = { telemetry: telemetry || {} };
    const domain = telemetry ? telemetry.domain : 'unknown';

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);
      const res = await fetch('http://127.0.0.1:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (!res.ok) throw new Error('Status: ' + res.status);
      const data = await res.json();
      return {
        domain: domain,
        url: telemetry ? telemetry.url : '',
        score: data.ai_verdict ? data.ai_verdict.safety_score : 50,
        threatScore: data.ai_verdict ? 100 - data.ai_verdict.safety_score : 50,
        verdict: data.ai_verdict ? data.ai_verdict.verdict : 'suspicious',
        description: data.ai_verdict ? data.ai_verdict.summary : 'Anomalies detected.',
        flags: data.ai_verdict ? data.ai_verdict.top_risks : [],
        plainEnglishBriefing: data.ai_verdict ? data.ai_verdict.plain_english_briefing : null
      };
    } catch (err) {
      console.warn('Backend unavailable, running local analysis:', err.message);
      return computeLocalScore(telemetry || {}, domain);
    }
  }

  // Fetch trust profile separately so it never blocks the main scan
  async function fetchAndShowTrustProfile(domain) {
    const section = document.getElementById('section-trust-profile');
    if (!section) return;

    // Show it immediately with 'Loading...' state
    section.classList.remove('hidden');
    const ageEl = document.getElementById('trust-domain-age');
    const issuerEl = document.getElementById('trust-ssl-issuer');
    const validityEl = document.getElementById('trust-ssl-validity');
    if (ageEl) { ageEl.textContent = 'Looking up…'; ageEl.style.color = 'var(--text-tertiary)'; }
    if (issuerEl) { issuerEl.textContent = 'Looking up…'; issuerEl.style.color = 'var(--text-tertiary)'; }
    if (validityEl) { validityEl.textContent = 'Looking up…'; validityEl.style.color = 'var(--text-tertiary)'; }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000);
      const res = await fetch('http://127.0.0.1:8000/trust-profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (!res.ok) throw new Error('Status ' + res.status);
      const profile = await res.json();
      updateTrustProfile(profile);
    } catch (err) {
      console.warn('[TrustProfile] Fetch failed:', err.message);
      if (ageEl) { ageEl.textContent = 'Unavailable'; ageEl.style.color = 'var(--text-tertiary)'; }
      if (issuerEl) { issuerEl.textContent = 'Unavailable'; issuerEl.style.color = 'var(--text-tertiary)'; }
      if (validityEl) { validityEl.textContent = 'Unavailable'; validityEl.style.color = 'var(--text-tertiary)'; }
    }
  }

  function computeLocalScore(telemetry, domain) {
    let risk = 0;
    const flags = [];
    const trust = telemetry.trust || {};
    const links = telemetry.links || {};
    const dataFields = telemetry.dataFields || {};
    const security = telemetry.security || {};
    const hidden = telemetry.hiddenElements || {};
    const net = telemetry.network || {};

    // --- Trust signals (mirrors scorer.py exactly) ---
    if (!trust.isHttps) {
      risk += 30;
      flags.push('Site is not using HTTPS (unencrypted connection)');
    }
    if (!trust.hasPrivacyPolicy) {
      risk += 15;
      flags.push('No privacy policy link found');
    }
    if (!trust.hasTerms) {
      risk += 10;
      flags.push('No terms & conditions link found');
    }
    if (!trust.hasContact) {
      risk += 5;
      flags.push('No contact or support page found');
    }

    // --- Form analysis ---
    const extFormActions = telemetry.externalFormActions || 0;
    if (extFormActions > 0) {
      risk += 35;
      flags.push(`Form(s) submit data to an external domain (${extFormActions} found)`);
    }
    const suspiciousFormActions = telemetry.suspiciousFormActions || [];
    if (suspiciousFormActions.length > 0) {
      risk += 25;
      flags.push(`Suspicious form action URLs detected (${suspiciousFormActions.length})`);
    }
    if ((telemetry.loginForms || 0) > 0 && !trust.isHttps) {
      risk += 20;
      flags.push('Login form detected on an insecure (non-HTTPS) page');
    }

    // --- Keyword analysis (matches scorer.py severity-based scoring) ---
    const keywordCategories = telemetry.keywordCategories || {};
    const CATEGORY_WEIGHTS = {
      phishing: 35, credential_theft: 30, scam: 25,
      malware: 40, social_engineering: 25, financial: 20, urgency: 10
    };
    if (Object.keys(keywordCategories).length > 0) {
      let totalCatScore = 0;
      const catFlags = [];
      for (const [cat, data] of Object.entries(keywordCategories)) {
        const weight = CATEGORY_WEIGHTS[cat] || 15;
        const catScore = Math.min(data.count * (weight / 3), weight);
        totalCatScore += catScore;
        catFlags.push(`${data.count} ${cat.replace(/_/g, ' ')} keyword(s) detected (severity: ${data.maxSeverity})`);
      }
      risk += Math.min(totalCatScore, 50);
      flags.push(...catFlags.slice(0, 3));
      if (catFlags.length > 3) {
        flags.push(`Additional threat categories: ${Object.keys(keywordCategories).join(', ')}`);
      }
    } else {
      // Fallback for plain keyword list (no categories)
      const keywords = telemetry.detectedKeywords || [];
      const keywordSeverity = telemetry.keywordTotalSeverity || 0;
      if (keywordSeverity > 0) {
        risk += Math.min(keywordSeverity * 2, 30);
      } else if (keywords.length > 0) {
        risk += Math.min(keywords.length * 10, 25);
        flags.push(`Suspicious keywords detected: ${keywords.slice(0, 5).join(', ')}`);
      }
    }

    // --- Link analysis ---
    const shortened = links.shortenedUrls || 0;
    if (shortened > 0) {
      risk += Math.min(shortened * 10, 20);
      flags.push(`${shortened} shortened URL(s) found (destination hidden)`);
    }
    const suspiciousExtLinks = links.suspiciousExternalLinks || [];
    if (suspiciousExtLinks.length > 0) {
      risk += Math.min(suspiciousExtLinks.length * 8, 25);
      flags.push(`${suspiciousExtLinks.length} suspicious external link(s) detected (potential phishing)`);
    }
    const lowCredLinks = links.lowCredibilityLinks || [];
    if (lowCredLinks.length > 0) {
      risk += Math.min(lowCredLinks.length * 5, 15);
      flags.push(`${lowCredLinks.length} link(s) to low-credibility TLDs detected`);
    }

    // --- Data field analysis ---
    const cardFields = dataFields.creditCardFields || 0;
    if (cardFields > 0) {
      risk += 10;
      flags.push(`Credit card input fields detected (${cardFields} found)`);
    }
    // Multiple password fields on login page
    if ((telemetry.loginForms || 0) > 0 && (telemetry.passwordFields || 0) > 3) {
      risk += 10;
      flags.push(`Multiple password fields detected (${telemetry.passwordFields} found)`);
    }

    // --- Link ratio ---
    const extLinks = links.externalLinks || 0;
    const intLinks = links.internalLinks || 0;
    const totalLinks = extLinks + intLinks;
    if (totalLinks > 0 && (extLinks / totalLinks) > 0.8) {
      risk += 15;
      flags.push(`High external link ratio (${extLinks}/${totalLinks} links go off-domain)`);
    }

    // --- iframe analysis ---
    if ((telemetry.iframes || 0) > 8) {
      risk += 10;
      flags.push(`High number of iframes detected (${telemetry.iframes} iframes)`);
    }
    if ((hidden.tinyIframes || 0) > 0) {
      risk += 15;
      flags.push(`${hidden.tinyIframes} tiny/hidden iframe(s) detected (possible clickjacking)`);
    }
    if ((hidden.hiddenInputs || 0) > 50) {
      risk += 5;
      flags.push(`High number of hidden input fields (${hidden.hiddenInputs})`);
    }

    // --- Security headers ---
    if (!security.hasCSP && !trust.isHttps) {
      risk += 5;
      flags.push('Missing Content-Security-Policy (risk of XSS)');
    }

    // --- Network telemetry ---
    const thirdPartyReqs = net.thirdPartyRequests || 0;
    if (thirdPartyReqs > 80) {
      risk += 20;
      flags.push(`Excessive third-party requests (${thirdPartyReqs})`);
    } else if (thirdPartyReqs > 40) {
      risk += 10;
      flags.push(`High number of third-party requests (${thirdPartyReqs})`);
    }
    if ((net.trackingScripts || 0) > 0) {
      risk += 15;
      flags.push(`Tracking scripts detected (${net.trackingScripts})`);
    }
    if ((net.adScripts || 0) > 5) {
      risk += 10;
      flags.push(`Multiple advertising scripts (${net.adScripts})`);
    }
    if ((net.analyticsScripts || 0) > 8) {
      risk += 5;
      flags.push(`Multiple analytics scripts (${net.analyticsScripts})`);
    }

    risk = Math.min(risk, 100);
    const safety = 100 - risk;

    let verdict = 'safe';
    if (safety < 40) verdict = 'dangerous';
    else if (safety < 80) verdict = 'suspicious';

    // Build summary matching backend format
    const domainLabel = domain || telemetry.domain || 'the site';
    let summary = `Scanned ${domainLabel}.`;
    if (flags.length > 0) {
      summary += ` Found ${flags.length} issue${flags.length > 1 ? 's' : ''}:`;
      summary += ' ' + flags.slice(0, 3).join(' ');
      if (flags.length > 3) summary += ` and ${flags.length - 3} more.`;
    } else {
      summary += ' No significant issues detected.';
    }

    let briefing;
    if (verdict === 'dangerous') {
      briefing = `This site appears to be a fraudulent version of ${domainLabel}. It contains security warnings and suspicious forms designed to trick you into sharing sensitive data. Do not enter any personal or financial information on this page.`;
    } else if (verdict === 'suspicious') {
      briefing = `There are unusual signals on ${domainLabel} that suggest it may not be trustworthy. Some forms or links on this page could be collecting your information without your knowledge. Be cautious and avoid entering sensitive data.`;
    } else {
      briefing = `${domainLabel} appears to be a legitimate website with standard security measures in place. No obvious signs of phishing or deception were detected. You can browse safely, but always stay alert.`;
    }

    const exposure = safety >= 80 ? 'low' : safety >= 40 ? 'medium' : 'high';

    return {
      domain: domainLabel,
      score: safety,
      threatScore: risk,
      verdict,
      description: summary,
      flags,
      plainEnglishBriefing: briefing,
      dataExposureRisk: exposure
    };
  }

  function showResults(result, telemetry, deepResult) {
    // Hide landing, show results
    document.getElementById('state-landing').classList.add('hidden');
    document.getElementById('state-results').classList.remove('hidden');

    // Save to history
    saveScanToHistory(result);

    // --- Verdict Card ---
    const badge = document.getElementById('verdict-badge');
    const title = document.getElementById('verdict-title');
    const desc = document.getElementById('verdict-desc');
    const scoreNum = document.getElementById('verdict-score');
    const scoreFill = document.getElementById('verdict-score-fill');
    const urlEl = document.getElementById('verdict-url');

    badge.textContent = result.verdict === 'safe' ? 'Safe' : result.verdict === 'suspicious' ? 'Suspicious' : 'Dangerous';
    badge.className = 'verdict-badge ' + result.verdict;

    if (result.verdict === 'dangerous') {
      title.textContent = 'High risk detected — proceed with caution';
      desc.textContent = result.description || 'Multiple critical security anomalies identified.';
      scoreFill.style.background = 'var(--dangerous)';
    } else if (result.verdict === 'suspicious') {
      title.textContent = 'Some anomalies detected';
      desc.textContent = result.description || 'Several suspicious signals found on this page.';
      scoreFill.style.background = 'var(--suspicious)';
    } else {
      title.textContent = 'This site appears safe';
      desc.textContent = result.description || 'No significant threats detected.';
      scoreFill.style.background = 'var(--safe)';
    }

    const displayScore = result.score || 100 - (result.threatScore || 0);
    scoreNum.textContent = Math.round(displayScore) + '%';
    scoreFill.style.width = Math.round(displayScore) + '%';

    urlEl.textContent = result.url || (telemetry ? telemetry.url : '');

    // --- Plain English Risk Briefing ---
    const briefingEl = document.getElementById('plain-english-briefing');
    const briefingText = document.getElementById('briefing-text');
    if (result.plainEnglishBriefing && briefingText && briefingEl) {
      briefingText.textContent = result.plainEnglishBriefing;
      briefingEl.classList.remove('hidden');
    } else if (briefingEl) {
      briefingEl.classList.add('hidden');
    }

    // --- Risk Factors ---
    const riskSection = document.getElementById('section-risk-factors');
    const riskList = document.getElementById('risk-factors-list');
    const flags = result.flags || [];
    if (flags.length > 0) {
      riskSection.classList.remove('hidden');
      riskList.innerHTML = flags.map((f, i) => {
        const severity = i < Math.ceil(flags.length / 3) ? 'critical' :
                         i < Math.ceil(flags.length * 2 / 3) ? 'warning' : 'minor';
        return `<div class="risk-factor">
          <span class="risk-dot ${severity}"></span>
          <span>${escapeHtml(f)}</span>
        </div>`;
      }).join('');
    } else {
      riskSection.classList.add('hidden');
    }

    // --- Deep Scan Results ---
    const deepSection = document.getElementById('section-deep-scan');
    const deepSummary = document.getElementById('deep-scan-summary');
    const deepPages = document.getElementById('deep-scan-pages');
    if (deepResult && deepResult.pages && deepResult.pages.length > 0) {
      deepSection.classList.remove('hidden');
      const ds = deepResult;
      const skipped = ds.sources && ds.sources.irrelevant_skipped ? ` (${ds.sources.irrelevant_skipped} non-relevant skipped)` : '';
      deepSummary.textContent = `Scanned ${ds.pages_count} page${ds.pages_count !== 1 ? 's' : ''} across the site${skipped}. Worst risk score: ${ds.aggregated.worst_score}%.`;

      const tLinks = telemetry.links || {};
      const tData = telemetry.dataFields || {};

      deepPages.innerHTML = ds.pages.map((page, idx) => {
        const score = page.pre_score || 0;
        const borderColor = score >= 60 ? 'var(--dangerous)' : score >= 30 ? 'var(--suspicious)' : 'var(--border)';
        const labelColor = score >= 60 ? 'var(--dangerous)' : score >= 30 ? 'var(--suspicious)' : 'var(--safe)';
        const labelText = score >= 60 ? 'High' : score >= 30 ? 'Med' : 'Low';

        let displayPath = '/';
        try { const pu = new URL(page.url); displayPath = pu.pathname + pu.search || '/'; } catch(e) { displayPath = page.url; }

        let detailsHtml = '';
        if (page.title) detailsHtml += `<div><span style="font-weight:600;">Title:</span> ${escapeHtml(page.title)}</div>`;

        // Merge browser telemetry into main page details
        if (idx === 0 && telemetry && telemetry.url) {
          const extLinks = tLinks.externalLinks || 0;
          detailsHtml += `<div><span style="font-weight:600;">External links:</span> ${extLinks}</div>`;
          if (telemetry.formCount > 0) detailsHtml += `<div><span style="font-weight:600;">Forms:</span> ${telemetry.formCount}</div>`;
          if (tData.emailFields > 0) detailsHtml += `<div><span style="font-weight:600;">Email fields:</span> ${tData.emailFields}</div>`;
          if (tData.phoneFields > 0) detailsHtml += `<div><span style="font-weight:600;">Phone fields:</span> ${tData.phoneFields}</div>`;
          if (tData.creditCardFields > 0) detailsHtml += `<div><span style="font-weight:600;">Credit card fields:</span> ${tData.creditCardFields}</div>`;
          if (tLinks.shortenedUrls > 0) detailsHtml += `<div><span style="font-weight:600;">Shortened URLs:</span> ${tLinks.shortenedUrls}</div>`;
          if (tLinks.suspiciousExternalLinks && tLinks.suspiciousExternalLinks.length > 0) detailsHtml += `<div><span style="color:#dc2626;font-weight:600;">Suspicious links:</span> <span style="color:#dc2626;">${tLinks.suspiciousExternalLinks.length}</span></div>`;
        }

        // Deep scan data for all pages
        if (page.loginForms > 0) detailsHtml += `<div><span style="font-weight:600;">Forms:</span> ${page.loginForms} login form${page.loginForms > 1 ? 's' : ''}</div>`;
        if (page.flagged_issues && page.flagged_issues.length > 0) {
          detailsHtml += `<div><span style="font-weight:600;">Issues:</span> <span style="color:#dc2626;">${page.flagged_issues.slice(0, 2).join('; ')}</span></div>`;
        }

        return `<div class="deep-page">
          <div class="deep-page-header">
            <span class="deep-page-path" title="${escapeHtml(page.url)}">${escapeHtml(displayPath)}</span>
            <span class="deep-page-score" style="background:${labelColor}20;color:${labelColor};">${labelText} ${score}</span>
          </div>
          ${detailsHtml ? `<div class="deep-page-details">${detailsHtml}</div>` : ''}
        </div>`;
      }).join('');
    } else {
      deepSection.classList.add('hidden');
    }

    // --- Credential Form Analysis ---
    updateCredentialAnalysis(telemetry);

    // --- Quick Stats ---
    const links = telemetry.links || {};
    const trust = telemetry.trust || {};
    document.getElementById('stat-links').textContent = links.externalLinks || 0;
    document.getElementById('stat-trackers').textContent = (trust.cookieCount || 0) + (telemetry.scriptCount || 0) + (telemetry.iframes || 0);
    document.getElementById('stat-forms').textContent = telemetry.formCount || 0;
    document.getElementById('stat-scripts').textContent = telemetry.scriptCount || 0;

    // --- Evidence Sections ---
    updateNetworkEvidence(telemetry.network || {});
    updateSecurityEvidence(telemetry);
    updatePermissionsEvidence(telemetry.permissions || {});
    updateHiddenElementsEvidence(telemetry.hiddenElements || {});
    updateExternalLinksDetail(telemetry);
    updateSuspiciousLinks(telemetry);
    updateTrackerRanking(telemetry.network || {});
    updateSecurityTip();

    // Trust Profile is fetched separately (see fetchAndShowTrustProfile)
    // Hide it initially so stale data from last scan doesn't show
    const trustSection = document.getElementById('section-trust-profile');
    if (trustSection) trustSection.classList.add('hidden');

    // --- Network Map (draw on canvas in background tab) ---
    _lastNetworkData = telemetry.network || {};
    _lastRootDomain = result.domain || '';
    _lastVerdict = result.verdict || 'safe';
    drawNetworkMap(_lastNetworkData, _lastRootDomain, _lastVerdict);

    // Scroll to top of results
    document.getElementById('main-viewport').scrollTop = 0;
  }

  function updateTrustProfile(profile) {
    const section = document.getElementById('section-trust-profile');
    if (!section) return;

    if (!profile) {
      section.classList.add('hidden');
      return;
    }

    section.classList.remove('hidden');

    const ageEl = document.getElementById('trust-domain-age');
    const issuerEl = document.getElementById('trust-ssl-issuer');
    const validityEl = document.getElementById('trust-ssl-validity');

    if (ageEl) {
      ageEl.textContent = profile.age_description || 'Unavailable';
      if (profile.is_new_domain) {
        ageEl.style.color = 'var(--dangerous)';
      } else if (profile.age_description && profile.age_description !== 'Unavailable') {
        ageEl.style.color = 'var(--safe)';
      } else {
        ageEl.style.color = 'var(--text-primary)';
      }
    }

    if (issuerEl) {
      const issuer = profile.ssl_issuer || 'Unavailable';
      issuerEl.textContent = issuer.length > 28 ? issuer.substring(0, 26) + '…' : issuer;
      issuerEl.style.color = (issuer === 'Unavailable' || issuer === 'Unknown') ? 'var(--suspicious)' : 'var(--safe)';
    }

    if (validityEl) {
      const days = profile.ssl_days_remaining;
      if (days === null || days === undefined) {
        validityEl.textContent = 'Unknown';
        validityEl.style.color = 'var(--suspicious)';
      } else if (days < 0) {
        validityEl.textContent = 'Expired!';
        validityEl.style.color = 'var(--dangerous)';
        validityEl.style.fontWeight = '800';
      } else if (days < 30) {
        validityEl.textContent = `⚠ Expires in ${days} day${days !== 1 ? 's' : ''}`;
        validityEl.style.color = 'var(--dangerous)';
      } else if (days < 90) {
        validityEl.textContent = `${days} days remaining`;
        validityEl.style.color = 'var(--suspicious)';
      } else {
        validityEl.textContent = `${days} days remaining`;
        validityEl.style.color = 'var(--safe)';
      }
    }
  }

  // ======= NETWORK MAP: animated force-directed canvas graph =======
  let _mapAnimFrame = null;
  let _mapNodes = [];
  let _mapEdges = [];
  let _mapDrag = null;
  let _mapParticles = [];

  function drawNetworkMap(net, rootDomain, verdict) {
    const canvas = document.getElementById('network-map-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Cancel previous animation
    if (_mapAnimFrame) { cancelAnimationFrame(_mapAnimFrame); _mapAnimFrame = null; }

    const W = canvas.width || 334;
    const H = canvas.height || 338;

    const nodes = [];
    const edges = [];

    // Root node color based on verdict
    const rootColor = verdict === 'dangerous' ? '#ef4444' : verdict === 'suspicious' ? '#fbbf24' : '#3b82f6';

    nodes.push({
      id: 'root',
      label: rootDomain || 'This Site',
      x: W / 2, y: H / 2,
      vx: 0, vy: 0,
      r: 22,
      color: rootColor,
      pulse: 0,
      cat: 'root',
      reqCount: 0,
      fixed: false
    });

    _mapParticles = [];

    const catColors = { analytics: '#fbbf24', advertising: '#f97316', tracking: '#a855f7', other: '#94a3b8', cdn: '#06b6d4' };
    const groups = net.domainGroups || {};
    const rawDomains = net.thirdPartyDomains || [];
    const groupKeys = Object.keys(groups);
    const maxNodes = 14;
    let placed = 0;

    // Enhanced subdomain and categorization resolution
    if (groupKeys.length > 0) {
      const showSubdomains = groupKeys.length < 6;
      if (showSubdomains) {
        // Expand to show individual subdomains for low main-domain density
        const subNodes = [];
        groupKeys.forEach(main => {
          const g = groups[main];
          Object.keys(g.subdomains || {}).forEach(sub => {
            const fullDom = sub === 'www' ? main : `${sub}.${main}`;
            subNodes.push({ main, fullDom, count: g.subdomains[sub].count, categories: g.subdomains[sub].categories });
          });
        });

        subNodes.slice(0, maxNodes).forEach((nodeInfo, idx) => {
          const mainDomain = nodeInfo.fullDom;
          const h = mainDomain.toLowerCase();
          let topCat = 'other';
          if (h.includes('analytics') || h.includes('gtag') || h.includes('stat') || h.includes('mixpanel') || h.includes('scorecardresearch')) {
            topCat = 'analytics';
          } else if (h.includes('ad') || h.includes('doubleclick') || h.includes('pixel') || h.includes('adsystem') || h.includes('adnxs') || h.includes('pubmatic') || h.includes('rubiconproject') || h.includes('adservice')) {
            topCat = 'advertising';
          } else if (h.includes('track') || h.includes('beacon') || h.includes('collect') || h.includes('logger') || h.includes('telemetry')) {
            topCat = 'tracking';
          } else if (h.includes('cdn') || h.includes('static') || h.includes('assets') || h.includes('akamai') || h.includes('cloudfront') || h.includes('fastly') || h.includes('gstatic') || h.includes('images') || h.includes('edge')) {
            topCat = 'cdn';
          } else {
            let maxCount = 0;
            Object.keys(nodeInfo.categories || {}).forEach(cat => {
              if ((nodeInfo.categories[cat] || 0) > maxCount) { maxCount = nodeInfo.categories[cat]; topCat = cat; }
            });
          }

          const angle = (idx / Math.min(subNodes.length, maxNodes)) * 2 * Math.PI - Math.PI / 2;
          const ring = idx < 7 ? 105 : 155;
          const reqCount = nodeInfo.count || 1;
          const r = Math.min(7 + reqCount * 0.35, 14);

          nodes.push({
            id: mainDomain, label: mainDomain,
            x: W / 2 + Math.cos(angle) * ring + (Math.random() - 0.5) * 20,
            y: H / 2 + Math.sin(angle) * ring + (Math.random() - 0.5) * 20,
            vx: (Math.random()-0.5)*0.4, vy: (Math.random()-0.5)*0.4,
            r, color: catColors[topCat] || '#64748b',
            pulse: 0, cat: topCat, reqCount, fixed: false
          });
          edges.push({ from: 'root', to: mainDomain, cat: topCat });
        });
      } else {
        // Standard grouped main-domain rendering
        groupKeys.slice(0, maxNodes).forEach((mainDomain, idx) => {
          const g = groups[mainDomain];
          const h = mainDomain.toLowerCase();
          let topCat = 'other';
          if (h.includes('analytics') || h.includes('gtag') || h.includes('stat') || h.includes('mixpanel') || h.includes('scorecardresearch')) {
            topCat = 'analytics';
          } else if (h.includes('ad') || h.includes('doubleclick') || h.includes('pixel') || h.includes('adsystem') || h.includes('adnxs') || h.includes('pubmatic') || h.includes('rubiconproject') || h.includes('adservice')) {
            topCat = 'advertising';
          } else if (h.includes('track') || h.includes('beacon') || h.includes('collect') || h.includes('logger') || h.includes('telemetry')) {
            topCat = 'tracking';
          } else if (h.includes('cdn') || h.includes('static') || h.includes('assets') || h.includes('akamai') || h.includes('cloudfront') || h.includes('fastly') || h.includes('gstatic') || h.includes('images') || h.includes('edge')) {
            topCat = 'cdn';
          } else {
            let maxCount = 0;
            const subKeys = Object.keys(g.subdomains || {});
            subKeys.forEach(sub => {
              const info = g.subdomains[sub];
              Object.keys(info.categories || {}).forEach(cat => {
                if ((info.categories[cat] || 0) > maxCount) { maxCount = info.categories[cat]; topCat = cat; }
              });
            });
          }

          const totalCount = groupKeys.length;
          const angleStep = (2 * Math.PI) / Math.min(totalCount, maxNodes);
          const angle = idx * angleStep - Math.PI / 2;
          const ring = placed < 7 ? 105 : 155;

          const nx = W / 2 + Math.cos(angle) * ring;
          const ny = H / 2 + Math.sin(angle) * ring;
          const subKeys = Object.keys(g.subdomains || {});
          const reqCount = subKeys.reduce((s, sub) => s + (g.subdomains[sub].count || 0), 0);
          const r = Math.min(7 + reqCount * 0.35, 15);

          nodes.push({
            id: mainDomain, label: mainDomain,
            x: nx + (Math.random() - 0.5) * 20, y: ny + (Math.random() - 0.5) * 20,
            vx: (Math.random()-0.5)*0.4, vy: (Math.random()-0.5)*0.4,
            r, color: catColors[topCat] || '#64748b',
            pulse: 0, cat: topCat, reqCount, fixed: false
          });
          edges.push({ from: 'root', to: mainDomain, cat: topCat });
          placed++;
        });
      }
    } else if (rawDomains.length > 0) {
      // Fallback: use raw domain list with generic categorization
      rawDomains.slice(0, maxNodes).forEach((dom, idx) => {
        const h = dom.toLowerCase();
        let cat = 'other';
        if (h.includes('analytics') || h.includes('gtag') || h.includes('stat') || h.includes('mixpanel') || h.includes('scorecardresearch')) cat = 'analytics';
        else if (h.includes('ad') || h.includes('doubleclick') || h.includes('pixel') || h.includes('adsystem') || h.includes('adnxs') || h.includes('pubmatic') || h.includes('rubiconproject') || h.includes('adservice')) cat = 'advertising';
        else if (h.includes('track') || h.includes('beacon') || h.includes('collect') || h.includes('logger') || h.includes('telemetry')) cat = 'tracking';
        else if (h.includes('cdn') || h.includes('static') || h.includes('assets') || h.includes('akamai') || h.includes('cloudfront') || h.includes('fastly') || h.includes('gstatic') || h.includes('images') || h.includes('edge')) cat = 'cdn';

        const totalCount = Math.min(rawDomains.length, maxNodes);
        const angle = (idx / totalCount) * 2 * Math.PI - Math.PI / 2;
        const ring = idx < 7 ? 100 : 148;
        nodes.push({
          id: dom, label: dom,
          x: W / 2 + Math.cos(angle) * ring, y: H / 2 + Math.sin(angle) * ring,
          vx: (Math.random()-0.5)*0.4, vy: (Math.random()-0.5)*0.4,
          r: 8, color: catColors[cat] || '#64748b',
          pulse: 0, cat, reqCount: 1, fixed: false
        });
        edges.push({ from: 'root', to: dom, cat });
      });
    }
    // else: no third-party data — will show clean state overlay

    _mapNodes = nodes;
    _mapEdges = edges;

    const totalConnections = net.thirdPartyRequests || rawDomains.length || 0;
    const totalDomains = net.thirdPartyDomainsCount || rawDomains.length || 0;
    const isClean = totalDomains === 0;

    // Tooltip
    const tooltip = document.getElementById('network-map-tooltip');
    let hoveredNode = null;

    function nodeAt(mx, my) {
      return _mapNodes.find(n => Math.hypot(n.x - mx, n.y - my) < n.r + 5);
    }

    canvas.onmousemove = (e) => {
      const rect = canvas.getBoundingClientRect();
      const scaleX = W / rect.width;
      const scaleY = H / rect.height;
      const mx = (e.clientX - rect.left) * scaleX;
      const my = (e.clientY - rect.top) * scaleY;

      if (_mapDrag) { _mapDrag.x = mx; _mapDrag.y = my; _mapDrag.fixed = true; return; }

      const node = nodeAt(mx, my);
      if (node !== hoveredNode) {
        hoveredNode = node;
        if (node && tooltip) {
          const catLabel = { analytics: 'Analytics tracker', advertising: 'Ad network', tracking: 'Tracking beacon', cdn: 'CDN / Static assets', other: 'Third-party domain', root: 'This Site' }[node.cat] || 'Domain';
          const reqInfo = node.reqCount > 0 && node.id !== 'root' ? `<br><span style="color:#94a3b8;">${node.reqCount} request${node.reqCount !== 1 ? 's' : ''}</span>` : '';
          tooltip.innerHTML = `<strong>${escapeHtml(node.label)}</strong><br><span style="color:#94a3b8;">${catLabel}</span>${reqInfo}`;
          tooltip.classList.remove('hidden');
          tooltip.style.left = Math.min(e.clientX - rect.left + 10, rect.width - 190) + 'px';
          tooltip.style.top = Math.max(e.clientY - rect.top - 40, 4) + 'px';
          canvas.style.cursor = 'pointer';
        } else {
          if (tooltip) tooltip.classList.add('hidden');
          canvas.style.cursor = 'grab';
        }
      } else if (hoveredNode && tooltip) {
        tooltip.style.left = Math.min(e.clientX - rect.left + 10, rect.width - 190) + 'px';
        tooltip.style.top = Math.max(e.clientY - rect.top - 40, 4) + 'px';
      }
    };
    canvas.onmousedown = (e) => {
      const rect = canvas.getBoundingClientRect();
      const node = nodeAt((e.clientX - rect.left) * (W / rect.width), (e.clientY - rect.top) * (H / rect.height));
      if (node) { _mapDrag = node; canvas.style.cursor = 'grabbing'; }
    };
    canvas.onmouseup = () => { if (_mapDrag) { _mapDrag.fixed = false; _mapDrag = null; } canvas.style.cursor = 'grab'; };
    canvas.onmouseleave = () => { if (tooltip) tooltip.classList.add('hidden'); hoveredNode = null; };

    let tick = 0;

    // Calculate Privacy Footprint Assessment metrics
    let numTrackersAndAds = 0;
    let numCdns = 0;
    let numOthers = 0;

    edges.forEach(edge => {
      const n = nodes.find(x => x.id === edge.to);
      const reqs = n ? n.reqCount : 1;
      if (edge.cat === 'analytics' || edge.cat === 'advertising' || edge.cat === 'tracking') {
        numTrackersAndAds += reqs;
      } else if (edge.cat === 'cdn') {
        numCdns += reqs;
      } else {
        numOthers += reqs;
      }
    });

    const totalWeight = numTrackersAndAds + numCdns + numOthers || 1;
    const pctTrackers = Math.round((numTrackersAndAds / totalWeight) * 100);
    const pctCdn = Math.round((numCdns / totalWeight) * 100);
    const pctOther = 100 - pctTrackers - pctCdn;

    const pctTrackersEl = document.getElementById('pct-trackers');
    const pctCdnEl = document.getElementById('pct-cdn');
    const pctOtherEl = document.getElementById('pct-other');
    const fillTrackersEl = document.getElementById('fill-trackers');
    const fillCdnEl = document.getElementById('fill-cdn');
    const fillOtherEl = document.getElementById('fill-other');

    if (pctTrackersEl) pctTrackersEl.textContent = pctTrackers + '%';
    if (pctCdnEl) pctCdnEl.textContent = pctCdn + '%';
    if (pctOtherEl) pctOtherEl.textContent = Math.max(0, pctOther) + '%';
    if (fillTrackersEl) fillTrackersEl.style.width = pctTrackers + '%';
    if (fillCdnEl) fillCdnEl.style.width = pctCdn + '%';
    if (fillOtherEl) fillOtherEl.style.width = Math.max(0, pctOther) + '%';

    // Privacy grading
    let grade = 'A+';
    let gradeColor = 'var(--safe)';
    let gradeBg = 'var(--safe-bg)';
    let briefing = '';

    if (isClean || totalDomains === 0) {
      grade = 'A+';
      gradeColor = 'var(--safe)';
      gradeBg = 'var(--safe-bg)';
      briefing = '✓ Excellent privacy profile. No third-party trackers or external requests were detected. Your activities on this page are completely private.';
    } else {
      if (pctTrackers === 0) {
        grade = 'A';
        gradeColor = 'var(--safe)';
        gradeBg = 'var(--safe-bg)';
        briefing = '✓ Strong privacy profile. Some third-party connections are present for styling or content delivery (CDNs), but no tracking networks or advertisers were found.';
      } else if (pctTrackers < 10) {
        grade = 'B';
        gradeColor = 'var(--accent)';
        gradeBg = 'var(--accent-bg)';
        briefing = '⚠ Good privacy profile. A small fraction of requests are sent to analytics networks. Most connections are for secure content delivery (CDNs).';
      } else if (pctTrackers < 25) {
        grade = 'C';
        gradeColor = 'var(--suspicious)';
        gradeBg = 'var(--suspicious-bg)';
        briefing = '⚠ Moderate privacy risk. The page has active tracking beacons or analytics networks monitoring user engagement. Enable Shield to restrict them.';
      } else if (pctTrackers < 50) {
        grade = 'D';
        gradeColor = '#f97316';
        gradeBg = 'rgba(249, 115, 22, 0.12)';
        briefing = '🚨 Elevated privacy risk. Up to a third of all background connections represent advertisers and user-profiling networks. Enabling Shield is strongly recommended.';
      } else {
        grade = 'F';
        gradeColor = 'var(--dangerous)';
        gradeBg = 'var(--dangerous-bg)';
        briefing = '🚨 Critical privacy risk. Over half of the background network footprint consists of tracking beacons and ad servers. Your browsing on this page is highly profiled.';
      }
    }

    const gradeEl = document.getElementById('privacy-grade');
    const briefingEl = document.getElementById('privacy-briefing');
    if (gradeEl) {
      gradeEl.textContent = grade;
      gradeEl.style.color = gradeColor;
      gradeEl.style.backgroundColor = gradeBg;
    }
    if (briefingEl) {
      briefingEl.textContent = briefing;
    }

    function simulate() {
      const REPEL = 3200, ATTRACT = 0.022, CENTER = 0.004, DAMPING = 0.86, LINK_REST = 115;

      for (let i = 0; i < _mapNodes.length; i++) {
        const n = _mapNodes[i];
        if (n.fixed || n === _mapDrag) continue;
        let fx = 0, fy = 0;

        for (let j = 0; j < _mapNodes.length; j++) {
          if (i === j) continue;
          const m = _mapNodes[j];
          const dx = n.x - m.x, dy = n.y - m.y;
          const dist = Math.max(Math.hypot(dx, dy), 1);
          const force = REPEL / (dist * dist);
          fx += (dx / dist) * force; fy += (dy / dist) * force;
        }

        _mapEdges.forEach(edge => {
          let other = null;
          if (edge.from === n.id) other = _mapNodes.find(x => x.id === edge.to);
          else if (edge.to === n.id) other = _mapNodes.find(x => x.id === edge.from);
          if (!other) return;
          const dx = other.x - n.x, dy = other.y - n.y;
          const dist = Math.max(Math.hypot(dx, dy), 1);
          const stretch = dist - LINK_REST;
          fx += (dx / dist) * stretch * ATTRACT; fy += (dy / dist) * stretch * ATTRACT;
        });

        fx += (W / 2 - n.x) * CENTER; fy += (H / 2 - n.y) * CENTER;
        n.vx = (n.vx + fx) * DAMPING; n.vy = (n.vy + fy) * DAMPING;
        n.x = Math.max(n.r + 4, Math.min(W - n.r - 4, n.x + n.vx));
        n.y = Math.max(n.r + 4, Math.min(H - n.r - 4, n.y + n.vy));
      }

      // Update particles
      _mapParticles = _mapParticles.filter(p => {
        p.progress += p.speed;
        return p.progress < 1;
      });
    }

    function render() {
      tick++;
      ctx.clearRect(0, 0, W, H);

      // Background
      const bgGrad = ctx.createRadialGradient(W/2, H/2, 0, W/2, H/2, W*0.6);
      bgGrad.addColorStop(0, '#12151f'); bgGrad.addColorStop(1, '#0c0e1a');
      ctx.fillStyle = bgGrad; ctx.fillRect(0, 0, W, H);

      if (isClean) {
        // Clean site: show a beautiful "no connections" state
        const pulse = 0.5 + 0.5 * Math.sin(tick * 0.03);
        // Concentric rings
        for (let ring = 3; ring >= 1; ring--) {
          ctx.beginPath();
          ctx.arc(W/2, H/2, 30 + ring * 28 + pulse * 8, 0, 2*Math.PI);
          ctx.strokeStyle = `rgba(201,162,39,${0.05 * (4 - ring)})`;
          ctx.lineWidth = 1; ctx.stroke();
        }
        // Root node
        const rootNode = _mapNodes[0];
        rootNode.pulse = (rootNode.pulse + 0.04) % (2*Math.PI);
        const pr = rootNode.r * (1 + 0.08 * Math.sin(rootNode.pulse));
        const glow = ctx.createRadialGradient(W/2, H/2, pr*0.3, W/2, H/2, pr*2);
        glow.addColorStop(0, rootColor + '20'); glow.addColorStop(1, 'transparent');
        ctx.beginPath(); ctx.arc(W/2, H/2, pr*2, 0, 2*Math.PI); ctx.fillStyle = glow; ctx.fill();
        ctx.beginPath(); ctx.arc(W/2, H/2, pr, 0, 2*Math.PI);
        const ng = ctx.createRadialGradient(W/2-pr*0.3, H/2-pr*0.3, pr*0.1, W/2, H/2, pr);
        ng.addColorStop(0, lightenColor(rootColor, 30)); ng.addColorStop(1, rootColor);
        ctx.fillStyle = ng; ctx.fill(); ctx.strokeStyle = 'rgba(255,255,255,0.7)'; ctx.lineWidth = 1.5; ctx.stroke();
        // Label
        ctx.font = "600 9px 'Space Grotesk', sans-serif"; ctx.fillStyle = '#e2e8f0'; ctx.textAlign = 'center';
        const rl = rootNode.label.length > 16 ? rootNode.label.substring(0,15)+'…' : rootNode.label;
        ctx.fillText(rl, W/2, H/2 + pr + 13);
        // Overlay text
        ctx.font = "700 13px 'Space Grotesk', sans-serif"; ctx.fillStyle = '#10b981'; ctx.textAlign = 'center';
        ctx.fillText('✓ Clean Connection Profile', W/2, H/2 + 70);
        ctx.font = "500 9px 'Space Grotesk', sans-serif"; ctx.fillStyle = '#8892aa';
        ctx.fillText('No third-party trackers detected on this page', W/2, H/2 + 86);
        return;
      }

      // Periodically spawn particles on random edges
      if (_mapEdges.length > 0 && Math.random() < 0.05) {
        const edge = _mapEdges[Math.floor(Math.random() * _mapEdges.length)];
        const isSafeCdn = edge.cat === 'cdn';
        _mapParticles.push({
          from: isSafeCdn ? edge.to : 'root',
          to: isSafeCdn ? 'root' : edge.to,
          progress: 0,
          speed: 0.008 + Math.random() * 0.012,
          cat: edge.cat
        });
      }

      // Draw edges
      _mapEdges.forEach(edge => {
        const fn = _mapNodes.find(n => n.id === edge.from);
        const tn = _mapNodes.find(n => n.id === edge.to);
        if (!fn || !tn) return;
        const catEdgeColors = { analytics: 'rgba(251,191,36,0.18)', advertising: 'rgba(249,115,22,0.18)', tracking: 'rgba(168,85,247,0.18)', cdn: 'rgba(6,182,212,0.15)', other: 'rgba(148,163,184,0.12)' };
        ctx.beginPath(); ctx.moveTo(fn.x, fn.y); ctx.lineTo(tn.x, tn.y);
        ctx.strokeStyle = catEdgeColors[edge.cat] || 'rgba(150,160,180,0.15)';
        ctx.lineWidth = 1.0; ctx.setLineDash([3, 5]); ctx.lineDashOffset = -(tick * 0.2); ctx.stroke(); ctx.setLineDash([]);
      });

      // Draw particles
      _mapParticles.forEach(p => {
        const fromNode = _mapNodes.find(n => n.id === p.from);
        const toNode = _mapNodes.find(n => n.id === p.to);
        if (!fromNode || !toNode) return;
        const px = fromNode.x + (toNode.x - fromNode.x) * p.progress;
        const py = fromNode.y + (toNode.y - fromNode.y) * p.progress;
        const catColors = { analytics: '#fbbf24', advertising: '#f97316', tracking: '#a855f7', other: '#94a3b8', cdn: '#06b6d4' };
        const color = catColors[p.cat] || '#94a3b8';
        ctx.beginPath(); ctx.arc(px, py, 2.0, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
      });

      // Draw nodes
      _mapNodes.forEach(node => {
        const isRoot = node.id === 'root';
        node.pulse = (node.pulse + (isRoot ? 0.04 : 0.015)) % (2 * Math.PI);
        const pm = isRoot ? 1 + 0.08 * Math.sin(node.pulse) : 1;
        const r = node.r * pm;

        const glow = ctx.createRadialGradient(node.x, node.y, r*0.3, node.x, node.y, r*2.0);
        glow.addColorStop(0, node.color + (isRoot ? '20' : '10')); glow.addColorStop(1, 'transparent');
        ctx.beginPath(); ctx.arc(node.x, node.y, r*2.0, 0, 2*Math.PI); ctx.fillStyle = glow; ctx.fill();

        ctx.beginPath(); ctx.arc(node.x, node.y, r, 0, 2*Math.PI);
        const ng = ctx.createRadialGradient(node.x-r*0.3, node.y-r*0.3, r*0.1, node.x, node.y, r);
        ng.addColorStop(0, lightenColor(node.color, 30)); ng.addColorStop(1, node.color);
        ctx.fillStyle = ng; ctx.fill();
        ctx.strokeStyle = 'rgba(255,255,255,0.75)'; ctx.lineWidth = isRoot ? 2.0 : 1.2; ctx.stroke();

        ctx.font = `${isRoot ? '700' : '500'} ${isRoot ? 9 : 8}px 'Space Grotesk', sans-serif`;
        ctx.fillStyle = '#e2e8f0'; ctx.textAlign = 'center';
        const label = node.label.length > 15 ? node.label.substring(0, 14) + '…' : node.label;
        ctx.fillText(label, node.x, node.y + r + 12);
      });

      // Stat overlay (top-left corner)
      ctx.fillStyle = 'rgba(24, 28, 48, 0.85)';
      ctx.beginPath();
      roundRect(ctx, 8, 8, 148, 34, 6);
      ctx.fill();
      ctx.font = "600 10px 'Space Grotesk', sans-serif"; ctx.fillStyle = '#f8fafc'; ctx.textAlign = 'left';
      ctx.fillText(`${totalConnections} reqs · ${totalDomains} domains`, 16, 22);
      ctx.font = "500 8px 'Space Grotesk', sans-serif"; ctx.fillStyle = '#8892aa';
      ctx.fillText('Third-party network activity', 16, 35);
    }

    function roundRect(ctx, x, y, w, h, r) {
      ctx.moveTo(x+r, y); ctx.lineTo(x+w-r, y); ctx.quadraticCurveTo(x+w, y, x+w, y+r);
      ctx.lineTo(x+w, y+h-r); ctx.quadraticCurveTo(x+w, y+h, x+w-r, y+h);
      ctx.lineTo(x+r, y+h); ctx.quadraticCurveTo(x, y+h, x, y+h-r);
      ctx.lineTo(x, y+r); ctx.quadraticCurveTo(x, y, x+r, y);
    }

    function loop() { simulate(); render(); _mapAnimFrame = requestAnimationFrame(loop); }
    loop();
  }

  function lightenColor(hex, amount) {
    try {
      const num = parseInt(hex.replace('#',''), 16);
      const r = Math.min(255, (num >> 16) + amount);
      const g = Math.min(255, ((num >> 8) & 0xff) + amount);
      const b = Math.min(255, (num & 0xff) + amount);
      return `rgb(${r},${g},${b})`;
    } catch { return hex; }
  }
  // ===== END NETWORK MAP =====

  function updateCredentialAnalysis(telemetry) {
    const section = document.getElementById('section-credentials');
    const content = document.getElementById('credential-content');
    if (!section || !content) return;

    const forms = telemetry.formCount || 0;
    const loginForms = telemetry.loginForms || 0;
    const passwordFields = telemetry.passwordFields || 0;
    const extActions = telemetry.externalFormActions || 0;
    const suspiciousActions = (telemetry.suspiciousFormActions || []).length;
    const ccFields = (telemetry.dataFields && telemetry.dataFields.creditCardFields) || 0;
    const isHttps = telemetry.trust && telemetry.trust.isHttps;

    if (forms === 0) {
      section.classList.add('hidden');
      return;
    }

    section.classList.remove('hidden');

    let hasCredentialForm = loginForms > 0 || passwordFields > 0;
    let isDangerous = extActions > 0 || suspiciousActions > 0 || (loginForms > 0 && !isHttps);
    let isSecure = isHttps && extActions === 0 && suspiciousActions === 0;

    let html = '';

    if (hasCredentialForm) {
      let cardClass = isDangerous ? 'credentials-card danger' : isSecure ? 'credentials-card secure' : 'credentials-card';
      html += `<div class="${cardClass}">`;
      html += `<div class="cred-title">${isDangerous ? '⚠ Credential Form at Risk' : '✓ Credential Form Detected'}</div>`;
      html += `<div class="cred-detail">`;
      if (loginForms > 0) html += `Login forms: ${loginForms}<br>`;
      if (passwordFields > 0) html += `Password fields: ${passwordFields}<br>`;
      if (ccFields > 0) html += `Credit card fields detected<br>`;
      if (extActions > 0) html += `<span style="color:#dc2626;">⚠ Submits data to external domain${extActions > 1 ? 's' : ''}</span><br>`;
      if (!isHttps) html += `<span style="color:#dc2626;">⚠ Not using HTTPS (data sent in plaintext)</span><br>`;
      if (suspiciousActions > 0) html += `<span style="color:#dc2626;">⚠ Suspicious form action URLs detected</span><br>`;
      html += `</div></div>`;
    }

    // Individual form details if available from external form actions
    if (extActions > 0 && telemetry.suspiciousFormActions) {
      telemetry.suspiciousFormActions.slice(0, 3).forEach(action => {
        html += `<div class="credentials-card danger" style="margin-top:6px;">
          <div class="cred-title">Suspicious form destination</div>
          <div class="cred-detail" style="word-break:break-all;">${escapeHtml(action)}</div>
        </div>`;
      });
    }

    if (!hasCredentialForm && forms > 0) {
      html += `<div style="font-size:10px;color:var(--text-sub);">${forms} form${forms > 1 ? 's' : ''} detected on this page (no login/password fields found).</div>`;
    }

    content.innerHTML = html;
  }

  function updateNetworkEvidence(net) {
    const setNet = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val != null ? val : 0;
    };
    setNet('net-requests', net.thirdPartyRequests);
    setNet('net-domains', net.thirdPartyDomainsCount);
    setNet('net-tracking', net.trackingScripts);
    setNet('net-analytics', net.analyticsScripts);
    setNet('net-ads', net.adScripts);
  }

  function updateSecurityEvidence(telemetry) {
    const trust = telemetry.trust || {};
    const security = telemetry.security || {};
    const setSec = (id, val, good) => {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = val;
        el.style.color = good ? 'var(--safe)' : 'var(--dangerous)';
      }
    };
    setSec('sec-https', trust.isHttps ? 'Yes' : 'No', trust.isHttps);
    setSec('sec-csp', security.hasCSP ? 'Present' : 'Missing', security.hasCSP);
    setSec('sec-xframe', security.hasXFrameOptions ? 'Present' : 'Missing', security.hasXFrameOptions);
    setSec('sec-privacy', trust.hasPrivacyPolicy ? 'Found' : 'Missing', trust.hasPrivacyPolicy);
    setSec('sec-terms', trust.hasTerms ? 'Found' : 'Missing', trust.hasTerms);
    setSec('sec-contact', trust.hasContact ? 'Found' : 'Missing', trust.hasContact);
  }

  function updatePermissionsEvidence(perms) {
    const setPerm = (id, val) => {
      const el = document.getElementById(id);
      if (el) {
        if (val === 'granted') { el.textContent = 'Granted'; el.style.color = 'var(--dangerous)'; }
        else if (val === 'prompt') { el.textContent = 'Prompt'; el.style.color = 'var(--suspicious)'; }
        else { el.textContent = 'Denied'; el.style.color = 'var(--safe)'; }
      }
    };
    setPerm('perm-geo', perms.geolocation);
    setPerm('perm-notif', perms.notifications);
    setPerm('perm-camera', perms.camera);
    setPerm('perm-mic', perms.microphone);
  }

  function updateHiddenElementsEvidence(hidden) {
    const setHe = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val != null ? val : 0;
    };
    setHe('he-iframes', (hidden.tinyIframes || 0) + (hidden.hiddenIframes || 0));
    setHe('he-inputs', hidden.hiddenInputs || 0);
    setHe('he-invisible', hidden.invisibleElements || 0);
  }

  function updateExternalLinksDetail(telemetry) {
    const container = document.getElementById('ext-links-list');
    if (!container) return;
    const links = telemetry.links || {};
    const extLinks = links.externalLinks || 0;
    const shortenedUrls = links.shortenedUrls || 0;
    const urls = links.externalLinkUrls || [];

    if (extLinks === 0 && shortenedUrls === 0) {
      container.innerHTML = '<span style="color:var(--text-sub);">No external links detected.</span>';
      return;
    }

    let html = '';
    html += '<div class="evidence-row"><span>Total external links</span><span style="font-weight:700;">' + extLinks + '</span></div>';
    if (shortenedUrls > 0) html += '<div class="evidence-row" style="color:#b45309;"><span>Shortened URLs</span><span style="font-weight:700;">' + shortenedUrls + '</span></div>';
    if (urls.length > 0) {
      html += '<div style="margin-top:6px;max-height:250px;overflow-y:auto;">';
      urls.forEach(u => {
        html += '<div style="font-size:9px;padding:3px 0;word-break:break-all;color:var(--text-sub);border-bottom:1px solid #f8fafc;">' + escapeHtml(u) + '</div>';
      });
      html += '</div>';
    }
    container.innerHTML = html;
  }

  function updateSuspiciousLinks(telemetry) {
    const container = document.getElementById('suspicious-links-list');
    if (!container) return;
    const links = telemetry.links || {};
    const suspicious = links.suspiciousLinkDomains || [];
    if (suspicious.length === 0) {
      container.innerHTML = '<span style="color:#10b981;">No suspicious external links detected.</span>';
      return;
    }
    container.innerHTML = suspicious.slice(0, 10).map(d =>
      '<div style="padding:2px 0;font-size:9px;color:#991b1b;">⚠ ' + escapeHtml(d) + '</div>'
    ).join('');
    if (suspicious.length > 10) container.innerHTML += '<div style="font-size:9px;color:var(--text-sub);">+' + (suspicious.length - 10) + ' more</div>';
  }

  function updateTrackerRanking(net) {
    const container = document.getElementById('tracker-ranking-list');
    if (!container) return;
    const groups = net.domainGroups || {};
    const keys = Object.keys(groups);
    if (keys.length === 0) {
      container.innerHTML = '<span style="color:#10b981;">No trackers detected.</span>';
      return;
    }

    const catSeverity = { tracking: 10, advertising: 8, analytics: 5, other: 2 };
    const catColors = { analytics:'#d97706', advertising:'#ea580c', tracking:'#2563eb', other:'#6b7280' };
    const catLabels = { analytics:'Analytics', advertising:'Ad', tracking:'Tracking', other:'Other' };

    const ranked = keys.map(main => {
      const g = groups[main];
      const subKeys = Object.keys(g.subdomains);
      let totalCatScore = 0, maxCat = 'other', maxCatCount = 0, totalReqs = 0;
      subKeys.forEach(sub => {
        const info = g.subdomains[sub];
        totalReqs += info.count;
        Object.keys(info.categories).forEach(cat => {
          const c = info.categories[cat];
          if (c > maxCatCount) { maxCatCount = c; maxCat = cat; }
          totalCatScore += catSeverity[cat] || 2;
        });
      });
      const score = Math.round((subKeys.length > 0 ? totalCatScore / subKeys.length : 2) + Math.min(totalReqs / 3, 12) + Math.min(subKeys.length * 3, 15));
      return { domain: main, score, subdomains: subKeys, totalReqs, topCat: maxCat };
    });
    ranked.sort((a, b) => b.score - a.score);

    container.innerHTML = ranked.slice(0, 5).map((item, idx) => {
      const cc = catColors[item.topCat] || '#6b7280';
      const cl = catLabels[item.topCat] || 'Other';
      const medalColor = idx === 0 ? '#dc2626' : idx === 1 ? '#d97706' : idx === 2 ? '#6b7280' : '#9ca3af';
      return '<div style="display:flex;align-items:center;gap:6px;padding:4px 0;' + (idx > 0 ? 'border-top:1px solid rgba(255,255,255,0.04);' : '') + '">' +
        '<span style="width:18px;height:18px;border-radius:50%;background:' + medalColor + '20;color:' + medalColor + ';display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:700;flex-shrink:0;">' + (idx + 1) + '</span>' +
        '<div style="flex:1;"><div style="font-size:10px;font-weight:600;">' + escapeHtml(item.domain) + ' <span style="background:' + cc + '15;color:' + cc + ';padding:0 4px;border-radius:3px;font-size:8px;font-weight:600;">' + cl + '</span></div>' +
        '<div style="font-size:8px;color:var(--text-secondary);">' + item.totalReqs + ' reqs · ' + item.subdomains.length + ' subs · Score: ' + item.score + '</div></div></div>';
    }).join('');
  }

  function updateSecurityTip() {
    const tipEl = document.getElementById('security-tip-text');
    if (!tipEl) return;
    const tips = [
      "Enable 2FA on all your critical accounts.",
      "Avoid clicking links in unsolicited emails.",
      "Use a password manager for unique passwords.",
      "Keep your browser and extensions updated.",
      "Check for HTTPS before entering sensitive data.",
      "Review app permissions and revoke unused access."
    ];
    tipEl.textContent = tips[Math.floor(Math.random() * tips.length)];
  }

  async function runDeepScan(url) {
    try {
      const res = await fetch('http://127.0.0.1:8000/analyze-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, deep: true })
      });
      if (!res.ok) throw new Error('Status: ' + res.status);
      const data = await res.json();
      return data.deep_scan || null;
    } catch (err) {
      console.warn('Deep scan failed:', err.message);
      return null;
    }
  }

  // --- History ---
  function saveScanToHistory(scanResult) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.session) return;
    chrome.storage.session.get(['sitesentinel_history'], (result) => {
      let history = result.sitesentinel_history || [];
      const now = new Date();
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const timeStr = `${months[now.getMonth()]} ${now.getDate()}, ${now.getFullYear()} &bull; ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

      history.unshift({
        domain: scanResult.domain,
        url: scanResult.url,
        score: scanResult.score,
        verdict: scanResult.verdict,
        dateStr: timeStr,
        description: scanResult.description,
        flags: scanResult.flags || [],
        threatScore: scanResult.threatScore || (100 - scanResult.score)
      });
      if (history.length > 50) history.pop();
      chrome.storage.session.set({ sitesentinel_history: history });
    });
  }

  // --- Shield ---
  function initShield() {
    const toggle = document.getElementById('toggle-shield');
    if (!toggle) return;

    fetchShieldStats();

    toggle.addEventListener('change', () => {
      const enabled = toggle.checked;
      chrome.runtime.sendMessage({ action: 'toggle_shield', enabled }, (resp) => {
        if (resp) updateShieldUI(resp.enabled, null);
      });
    });

    chrome.runtime.onMessage.addListener((msg) => {
      if (msg.action === 'shield_blocked' && msg.tabId === (activeTabInfo ? activeTabInfo.id : null)) {
        const countEl = document.getElementById('shield-blocked-count');
        if (countEl) {
          const current = parseInt(countEl.textContent) || 0;
          countEl.textContent = current + 1;
        }
      }
    });
  }

  function fetchShieldStats() {
    chrome.runtime.sendMessage({ action: 'get_shield_stats' }, (stats) => {
      if (!stats) return;
      updateShieldUI(stats.enabled, stats);
    });
  }

  function updateShieldUI(enabled, stats) {
    const toggle = document.getElementById('toggle-shield');
    const statusEl = document.getElementById('shield-status');
    const iconEl = document.getElementById('shield-icon');
    const countEl = document.getElementById('shield-blocked-count');
    if (toggle) toggle.checked = enabled;
    if (statusEl) {
      statusEl.textContent = enabled ? 'Active' : 'Off';
      statusEl.style.background = enabled ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255, 255, 255, 0.05)';
      statusEl.style.color = enabled ? '#34d399' : 'var(--text-secondary)';
    }
    if (iconEl) {
      iconEl.style.background = enabled ? 'var(--accent-bg)' : 'rgba(255, 255, 255, 0.05)';
      iconEl.style.color = enabled ? 'var(--accent)' : 'var(--text-tertiary)';
    }
    if (countEl && stats) {
      countEl.textContent = stats.blockedThisPage || 0;
    }
  }

  initShield();
  setTimeout(fetchShieldStats, 500);

  // --- Tabs ---
  function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-tab') === targetTab));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.getAttribute('id') === 'tab-' + targetTab));
        document.body.classList.toggle('network-map-mode', targetTab === 'network-map');
        if (targetTab === 'history') loadHistory();
        if (targetTab === 'network-map' && _lastNetworkData) {
          drawNetworkMap(_lastNetworkData, _lastRootDomain, _lastVerdict);
        }
      });
    });
  }

  function loadHistory() {
    const container = document.getElementById('tab-history');
    if (!container) return;
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.session) return;
    chrome.storage.session.get(['sitesentinel_history'], (result) => {
      const history = result.sitesentinel_history || [];
      if (history.length === 0) {
        container.innerHTML = '<div class="card" style="text-align:center;padding:24px;"><div style="font-size:10px;color:var(--text-secondary);">No scans yet. Click <strong>Scan Now</strong> to check a site.</div></div>';
        return;
      }
      container.innerHTML = history.map((item, idx) => {
        const v = item.verdict || 'unknown';
        const badgeColor = v === 'safe' ? '#10b981' : v === 'suspicious' ? '#f59e0b' : '#dc2626';
        const icon = v === 'safe' ? '&#10003;' : v === 'suspicious' ? '&#9888;' : '&#10007;';
        const flagHtml = (item.flags || []).slice(0, 3).map(f =>
          '<span style="background:rgba(201, 162, 39, 0.06);color:#8892aa;padding:1px 6px;border-radius:4px;font-size:8px;border:1px solid rgba(201, 162, 39, 0.18);">' + escapeHtml(f) + '</span>'
        ).join('');
        return '<div class="card" style="padding:10px;margin-bottom:6px;cursor:pointer;background:rgba(201, 162, 39, 0.03);border:1px solid rgba(201, 162, 39, 0.15);" data-idx="' + idx + '">' +
          '<div style="display:flex;align-items:center;gap:8px;">' +
          '<span style="width:24px;height:24px;border-radius:50%;background:' + badgeColor + '20;color:' + badgeColor + ';display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;">' + icon + '</span>' +
          '<div style="flex:1;min-width:0;">' +
          '<div style="font-size:10px;font-weight:600;">' + escapeHtml(item.domain || '') + '</div>' +
          '<div style="font-size:8px;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(item.url || '') + '</div>' +
          '</div>' +
          '<div style="text-align:right;flex-shrink:0;">' +
          '<div style="font-size:10px;font-weight:700;color:' + badgeColor + ';">' + v.charAt(0).toUpperCase() + v.slice(1) + '</div>' +
          '<div style="font-size:8px;color:var(--text-secondary);">' + (item.dateStr || '') + '</div>' +
          '</div>' +
          '</div>' +
          (flagHtml ? '<div style="display:flex;gap:4px;margin-top:6px;flex-wrap:wrap;">' + flagHtml + '</div>' : '') +
          '</div>';
      }).join('');
    });
  }

  // --- Settings ---
  function initSettings() {
    const defaultSettings = {
      realtime: true,
      deepScan: true,
      whitelist: []
    };

    let settings = defaultSettings;
    try {
      const stored = localStorage.getItem('sitesentinel_settings');
      if (stored) settings = JSON.parse(stored);
    } catch (_) {}
    if (!settings.whitelist) settings.whitelist = [];

    // Bind toggle events once
    const bindToggle = (id, key) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.checked = settings[key] !== false;
      el.addEventListener('change', (e) => {
        settings[key] = e.target.checked;
        saveSettings(settings);
      });
    };
    bindToggle('toggle-realtime', 'realtime');
    bindToggle('toggle-deep-scan', 'deepScan');

    // Bind Add button once
    const whitelistInput = document.getElementById('input-whitelist-domain');
    const addBtn = document.getElementById('btn-add-whitelist');
    if (addBtn && whitelistInput) {
      addBtn.addEventListener('click', () => {
        let domain = whitelistInput.value.trim().toLowerCase();
        if (!domain) return;
        try {
          if (domain.includes('://')) domain = new URL(domain).hostname;
        } catch (e) {}
        domain = domain.replace(/^www\./, '');
        if (!settings.whitelist.includes(domain)) {
          settings.whitelist.push(domain);
          saveSettings(settings);
          renderWhitelist(settings.whitelist);
        }
        whitelistInput.value = '';
      });
    }

    // Initial render
    renderWhitelist(settings.whitelist);

    // Sync whitelist from chrome.storage.local (background.js may have
    // added domains via "Don't warn again")
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['sitesentinel_settings'], (result) => {
        if (result.sitesentinel_settings) {
          const bgWhitelist = result.sitesentinel_settings.whitelist || [];
          const merged = [...new Set([...settings.whitelist, ...bgWhitelist])];
          if (merged.length !== settings.whitelist.length) {
            settings.whitelist = merged;
            localStorage.setItem('sitesentinel_settings', JSON.stringify(settings));
            renderWhitelist(settings.whitelist);
          }
        }
      });
    }
  }

  function renderWhitelist(whitelist) {
    const container = document.getElementById('whitelist-domains');
    if (!container) return;
    if (!whitelist || whitelist.length === 0) {
      container.innerHTML = 'No trusted sites added.';
      return;
    }
    container.innerHTML = whitelist.map(domain =>
      '<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:11px;">' +
      '<span>' + escapeHtml(domain) + '</span>' +
      '<button class="remove-wl" data-domain="' + escapeHtml(domain) + '" style="background:none;border:none;color:#ef4444;cursor:pointer;font-size:14px;">&times;</button>' +
      '</div>'
    ).join('');
    container.querySelectorAll('.remove-wl').forEach(btn => {
      btn.addEventListener('click', () => {
        const domain = btn.getAttribute('data-domain');
        let settings = { whitelist: [] };
        try {
          const stored = localStorage.getItem('sitesentinel_settings');
          if (stored) settings = JSON.parse(stored);
        } catch (_) {}
        settings.whitelist = (settings.whitelist || []).filter(d => d !== domain);
        saveSettings(settings);
        renderWhitelist(settings.whitelist);
      });
    });
  }

  function saveSettings(settings) {
    localStorage.setItem('sitesentinel_settings', JSON.stringify(settings));
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set({ sitesentinel_settings: settings });
    }
  }
});
