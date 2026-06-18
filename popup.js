document.addEventListener('DOMContentLoaded', () => {
  let activeTabInfo = null;
  let activeTelemetry = null;

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

    // Step 3: Take screenshot
    loadingText.textContent = 'Capturing page screenshot...';
    const screenshot = await captureScreenshot(activeTabInfo.windowId);

    // Step 4: Send to backend for analysis
    loadingText.textContent = 'Running security analysis...';
    const scanResult = await analyzePage(telemetry, screenshot);

    // Step 5: Run deep scan
    let deepResult = null;
    try {
      const stored = localStorage.getItem('sitesentinel_settings');
      if (stored) {
        const settings = JSON.parse(stored);
        if (settings.deepScan !== false && activeTabInfo.url) {
          loadingText.textContent = 'Crawling site pages...';
          deepResult = await runDeepScan(activeTabInfo.url);
        }
      }
    } catch (_) {}

    overlay.classList.add('hidden');

    // Step 6: Show all results
    showResults(scanResult, telemetry, deepResult);

    // Cache scan result so reopening popup on same page shows results immediately
    cacheScanResult(scanResult, telemetry, deepResult);
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

  function captureScreenshot(windowId) {
    return new Promise((resolve) => {
      if (!chrome.runtime || !chrome.runtime.sendMessage) {
        resolve(null);
        return;
      }
      chrome.runtime.sendMessage({ action: "capture_screenshot", windowId: windowId }, (resp) => {
        if (chrome.runtime.lastError || !resp || resp.error) {
          resolve(null);
          return;
        }
        resolve(resp.screenshot || null);
      });
    });
  }

  async function analyzePage(telemetry, screenshotData) {
    const payload = { telemetry: telemetry || {} };
    if (screenshotData) {
      payload.screenshot = screenshotData.split(',')[1];
    }
    const domain = telemetry ? telemetry.domain : 'unknown';

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
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
        plainEnglishBriefing: data.ai_verdict ? data.ai_verdict.plain_english_briefing : null,
        visionVerdict: data.vision_verdict || null
      };
    } catch (err) {
      console.warn('Backend unavailable, running local analysis:', err.message);
      return computeLocalScore(telemetry || {}, domain);
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

    if (!trust.isHttps) { risk += 30; flags.push("Site is not using HTTPS"); }
    if (!trust.hasPrivacyPolicy) { risk += 15; flags.push("No privacy policy link found"); }
    if (!trust.hasTerms) { risk += 10; flags.push("No terms & conditions link found"); }
    if (!trust.hasContact) { risk += 5; flags.push("No contact or support page found"); }
    if (telemetry.externalFormActions > 0) { risk += 35; flags.push("Form(s) submit data to an external domain"); }
    const suspiciousFormActions = telemetry.suspiciousFormActions || [];
    if (suspiciousFormActions.length > 0) { risk += 25; flags.push("Suspicious form action URLs detected"); }
    if (telemetry.loginForms > 0 && !trust.isHttps) { risk += 20; flags.push("Login form on insecure page"); }

    const keywords = telemetry.detectedKeywords || [];
    if (keywords.length > 0) { risk += 15; flags.push("Suspicious keywords detected (" + keywords.length + ")"); }

    const shortened = links.shortenedUrls || 0;
    if (shortened > 0) { risk += Math.min(shortened * 10, 20); flags.push("Shortened URLs found"); }

    const suspiciousExtLinks = links.suspiciousExternalLinks || [];
    if (suspiciousExtLinks.length > 0) { risk += Math.min(suspiciousExtLinks.length * 8, 25); flags.push("Suspicious external links detected"); }

    const lowCredLinks = links.lowCredibilityLinks || [];
    if (lowCredLinks.length > 0) { risk += Math.min(lowCredLinks.length * 5, 15); flags.push("Low-credibility TLD links"); }

    const cardFields = dataFields.creditCardFields || 0;
    if (cardFields > 0) { risk += 10; flags.push("Credit card input fields detected"); }

    const extLinks = links.externalLinks || 0;
    const intLinks = links.internalLinks || 0;
    const totalLinks = extLinks + intLinks;
    if (totalLinks > 0 && (extLinks / totalLinks) > 0.8) { risk += 15; flags.push("High external link ratio"); }

    if ((telemetry.iframes || 0) > 3) { risk += 10; flags.push("High number of iframes detected"); }
    if ((hidden.tinyIframes || 0) > 0) { risk += 15; flags.push("Tiny/hidden iframes detected (possible clickjacking)"); }
    if (!security.hasCSP) { risk += 5; flags.push("Missing Content-Security-Policy"); }

    const thirdPartyReqs = net.thirdPartyRequests || 0;
    if (thirdPartyReqs > 50) { risk += 20; flags.push("Excessive third-party requests (" + thirdPartyReqs + ")"); }
    else if (thirdPartyReqs > 20) { risk += 10; flags.push("High number of third-party requests"); }
    if ((net.trackingScripts || 0) > 0) { risk += 15; flags.push("Tracking scripts detected"); }
    if ((net.adScripts || 0) > 5) { risk += 10; flags.push("Multiple advertising scripts"); }

    risk = Math.min(risk, 100);
    const safety = 100 - risk;

    let verdict = 'safe';
    if (safety < 40) verdict = 'dangerous';
    else if (safety < 80) verdict = 'suspicious';

    let summary = `Scanned ${domain}.`;
    if (flags.length > 0) {
      summary += ` Found ${flags.length} issue${flags.length > 1 ? 's' : ''}: ${flags.slice(0, 3).join('; ')}`;
      if (flags.length > 3) summary += ` and ${flags.length - 3} more.`;
    } else {
      summary += " No significant issues detected.";
    }

    let briefing;
    if (verdict === 'dangerous') {
      briefing = `This site appears to be a fraudulent version of ${domain}. It contains security warnings and suspicious forms designed to trick you into sharing sensitive data. Do not enter any personal or financial information on this page.`;
    } else if (verdict === 'suspicious') {
      briefing = `There are unusual signals on ${domain} that suggest it may not be trustworthy. Some forms or links on this page could be collecting your information without your knowledge. Be cautious and avoid entering sensitive data.`;
    } else {
      briefing = `${domain} appears to be a legitimate website with standard security measures in place. No obvious signs of phishing or deception were detected. You can browse safely, but always stay alert.`;
    }

    return { domain, score: safety, threatScore: risk, verdict, description: summary, flags, plainEnglishBriefing: briefing, visionVerdict: null };
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
      scoreFill.style.background = '#dc2626';
    } else if (result.verdict === 'suspicious') {
      title.textContent = 'Some anomalies detected';
      desc.textContent = result.description || 'Several suspicious signals found on this page.';
      scoreFill.style.background = '#f59e0b';
    } else {
      title.textContent = 'This site appears safe';
      desc.textContent = result.description || 'No significant threats detected.';
      scoreFill.style.background = '#2563eb';
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

    // --- Vision Analysis ---
    const visionSection = document.getElementById('section-vision-analysis');
    const visionContent = document.getElementById('vision-content');
    if (result.visionVerdict && visionSection && visionContent) {
      visionSection.classList.remove('hidden');
      let html = '<div class="vision-grid">';

      if (result.visionVerdict.vision_analysis) {
        html += `<div class="vision-analysis-line">${escapeHtml(result.visionVerdict.vision_analysis)}</div>`;
      }

      if (result.visionVerdict.brand_impersonation && result.visionVerdict.brand_impersonation.detected) {
        const brand = result.visionVerdict.brand_impersonation.suspected_brand || 'unknown brand';
        html += `<div class="vision-item danger"><span class="vision-label">Brand Impersonation</span><span>${escapeHtml(brand)}</span></div>`;
      }

      if (result.visionVerdict.fake_badges && result.visionVerdict.fake_badges.detected) {
        html += `<div class="vision-item danger"><span class="vision-label">Fake Badges</span><span>${escapeHtml(result.visionVerdict.fake_badges.badges_found.join(', '))}</span></div>`;
      }

      if (result.visionVerdict.urgency_tactics && result.visionVerdict.urgency_tactics.detected) {
        html += `<div class="vision-item warning"><span class="vision-label">Urgency Tactics</span><span>${escapeHtml(result.visionVerdict.urgency_tactics.elements_found.join(', '))}</span></div>`;
      }

      if (result.visionVerdict.cloned_ui && result.visionVerdict.cloned_ui.detected) {
        html += `<div class="vision-item warning"><span class="vision-label">Cloned UI</span><span>${escapeHtml(result.visionVerdict.cloned_ui.details)}</span></div>`;
      }

      if (result.visionVerdict.visual_flags && result.visionVerdict.visual_flags.length > 0) {
        result.visionVerdict.visual_flags.forEach(f => {
          html += `<div class="vision-item danger"><span class="vision-label">Flag</span><span>${escapeHtml(f)}</span></div>`;
        });
      }

      html += '</div>';

      if (result.visionVerdict.visual_risk_score != null) {
        const vs = result.visionVerdict.visual_risk_score;
        const vColor = vs >= 60 ? '#dc2626' : vs >= 30 ? '#f59e0b' : '#10b981';
        html += `<div style="margin-top:8px;display:flex;align-items:center;gap:8px;">
          <span style="font-size:9px;color:var(--text-sub);font-weight:600;">Visual Risk</span>
          <div class="progress-bar-container" style="flex:1;"><div class="progress-bar-fill" style="width:${vs}%;background:${vColor};"></div></div>
          <span style="font-size:11px;font-weight:700;color:${vColor};">${vs}%</span>
        </div>`;
      }

      visionContent.innerHTML = html;
    } else if (visionSection) {
      visionSection.classList.add('hidden');
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
        const borderColor = score >= 60 ? '#dc2626' : score >= 30 ? '#d97706' : '#e2e8f0';
        const labelColor = score >= 60 ? '#dc2626' : score >= 30 ? '#d97706' : '#10b981';
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

    // Scroll to top of results
    document.getElementById('main-viewport').scrollTop = 0;
  }

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
        el.style.color = good ? '#10b981' : '#ef4444';
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
        if (val === 'granted') { el.textContent = 'Granted'; el.style.color = '#ef4444'; }
        else if (val === 'prompt') { el.textContent = 'Prompt'; el.style.color = '#f59e0b'; }
        else { el.textContent = 'Denied'; el.style.color = '#10b981'; }
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
      return '<div style="display:flex;align-items:center;gap:6px;padding:4px 0;' + (idx > 0 ? 'border-top:1px solid #f3f4f6;' : '') + '">' +
        '<span style="width:18px;height:18px;border-radius:50%;background:' + medalColor + '20;color:' + medalColor + ';display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:700;flex-shrink:0;">' + (idx + 1) + '</span>' +
        '<div style="flex:1;"><div style="font-size:10px;font-weight:600;">' + escapeHtml(item.domain) + ' <span style="background:' + cc + '15;color:' + cc + ';padding:0 4px;border-radius:3px;font-size:8px;font-weight:600;">' + cl + '</span></div>' +
        '<div style="font-size:8px;color:var(--text-sub);">' + item.totalReqs + ' reqs · ' + item.subdomains.length + ' subs · Score: ' + item.score + '</div></div></div>';
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

  // --- Tabs ---
  function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-tab') === targetTab));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.getAttribute('id') === 'tab-' + targetTab));
        if (targetTab === 'history') loadHistory();
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
        container.innerHTML = '<div class="card" style="text-align:center;padding:24px;"><div style="font-size:10px;color:var(--text-sub);">No scans yet. Click <strong>Scan Now</strong> to check a site.</div></div>';
        return;
      }
      container.innerHTML = history.map((item, idx) => {
        const v = item.verdict || 'unknown';
        const badgeColor = v === 'safe' ? '#10b981' : v === 'suspicious' ? '#f59e0b' : '#dc2626';
        const icon = v === 'safe' ? '&#10003;' : v === 'suspicious' ? '&#9888;' : '&#10007;';
        const flagHtml = (item.flags || []).slice(0, 3).map(f =>
          '<span style="background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:8px;">' + escapeHtml(f) + '</span>'
        ).join('');
        return '<div class="card" style="padding:10px;margin-bottom:6px;cursor:pointer;" data-idx="' + idx + '">' +
          '<div style="display:flex;align-items:center;gap:8px;">' +
          '<span style="width:24px;height:24px;border-radius:50%;background:' + badgeColor + '20;color:' + badgeColor + ';display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;">' + icon + '</span>' +
          '<div style="flex:1;min-width:0;">' +
          '<div style="font-size:10px;font-weight:600;">' + escapeHtml(item.domain || '') + '</div>' +
          '<div style="font-size:8px;color:var(--text-sub);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(item.url || '') + '</div>' +
          '</div>' +
          '<div style="text-align:right;flex-shrink:0;">' +
          '<div style="font-size:10px;font-weight:700;color:' + badgeColor + ';">' + v.charAt(0).toUpperCase() + v.slice(1) + '</div>' +
          '<div style="font-size:8px;color:var(--text-sub);">' + (item.dateStr || '') + '</div>' +
          '</div>' +
          '</div>' +
          (flagHtml ? '<div style="display:flex;gap:4px;margin-top:4px;flex-wrap:wrap;">' + flagHtml + '</div>' : '') +
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

    const bindToggle = (id, key) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.checked = settings[key] !== false;
      el.addEventListener('change', (e) => {
        settings[key] = e.target.checked;
        saveSettings(settings);
        if (key === 'realtime') {
          if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.set({ sitesentinel_settings: settings });
          }
        }
      });
    };

    bindToggle('toggle-realtime', 'realtime');
    bindToggle('toggle-deep-scan', 'deepScan');

    // Whitelist
    renderWhitelist(settings.whitelist);
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
