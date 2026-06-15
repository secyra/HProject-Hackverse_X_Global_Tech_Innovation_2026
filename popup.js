document.addEventListener('DOMContentLoaded', () => {
  let activeTabInfo = null;
  let activeTelemetry = null;

  // Initializations
  initTabs();
  initSettings();
  initHistory();
  wireupSettingsLinks();

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fetchDownloadProtectionStats() {
    if (typeof chrome === 'undefined' || !chrome.runtime) return;
    chrome.runtime.sendMessage({ action: 'get_download_protection_stats' }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.stats) return;
      const stats = resp.stats;
      const blockedEl = document.getElementById('dp-blocked');
      const warnedEl = document.getElementById('dp-warned');
      const recentEl = document.getElementById('dp-recent');
      const statusEl = document.getElementById('dp-status');
      if (blockedEl) blockedEl.textContent = stats.totalBlocked || 0;
      if (warnedEl) warnedEl.textContent = stats.totalWarned || 0;
      if (recentEl) {
        const blocks = stats.recentBlocks || [];
        if (blocks.length === 0) {
          recentEl.textContent = 'No recent blocked downloads.';
        } else {
          recentEl.innerHTML = blocks.slice(0, 5).map(b => {
            const domain = (() => { try { return new URL(b.url).hostname; } catch (e) { return 'unknown'; } })();
            return '<div style="display:flex;justify-content:space-between;padding:3px 0;border-top:1px solid #f3f4f6;font-size:9px;">' +
              '<span style="color:#b91c1c;font-weight:600;">' + escapeHtml(domain) + '</span>' +
              '<span style="color:var(--text-sub);">blocked</span></div>';
          }).join('');
        }
      }
      if (statusEl) {
        chrome.storage.local.get(['sitesentinel_settings'], (result) => {
          const settings = result.sitesentinel_settings || {};
          const active = settings.downloadProtection !== false;
          statusEl.textContent = active ? 'Active' : 'Off';
          statusEl.style.cssText = active
            ? 'font-size:9px;font-weight:700;padding:3px 8px;border-radius:10px;background:#dcfce7;color:#166534;'
            : 'font-size:9px;font-weight:700;padding:3px 8px;border-radius:10px;background:#f3f4f6;color:#6b7280;';
        });
      }
    });
  }
  
  // Query active tab for domain and telemetry
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (!tab) return;
      activeTabInfo = tab;

      let domain = 'N/A';
      try {
        domain = new URL(tab.url).hostname;
      } catch (_) {}

      // Update Safe State UI Header/Labels immediately
      const safeDomainLabel = document.getElementById('safe-domain-label');
      if (safeDomainLabel) safeDomainLabel.textContent = domain;

      // Check for previously stored warning for this domain
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['sitesentinel_domain_warnings'], (result) => {
          const warnings = result.sitesentinel_domain_warnings || {};
          const stored = warnings[domain];
          if (stored && stored.verdict !== 'safe') {
            const dashboardSafe = document.getElementById('dashboard-safe');
            if (dashboardSafe) dashboardSafe.classList.add('hidden');
            const dashboardRisk = document.getElementById('dashboard-risk');
            if (dashboardRisk) {
              dashboardRisk.classList.remove('hidden');
              const scoreValLabel = document.getElementById('risk-score-val');
              if (scoreValLabel) scoreValLabel.textContent = Math.round(stored.threatScore || 100 - stored.score) + '%';
              const riskDomainUrl = document.getElementById('risk-domain-url');
              if (riskDomainUrl) riskDomainUrl.textContent = stored.url || domain;
              animateRiskDial(stored.threatScore || 100 - stored.score);
              renderRiskFactors(stored.flags || []);
              if (activeTelemetry) renderRiskBreakdownDetails(activeTelemetry);
            }
          }
        });
      }
      
      // Request DOM telemetry from content.js
      if (chrome.tabs.sendMessage) {
        chrome.tabs.sendMessage(tab.id, { action: "get_telemetry" }, (response) => {
          if (chrome.runtime.lastError || !response) {
            activeTelemetry = {
              url: tab.url,
              domain: domain,
              title: tab.title,
              formCount: 0,
              trust: { isHttps: tab.url.startsWith('https:') }
            };
            fetchNetworkTelemetry(tab.id, activeTelemetry);
            return;
          }

          activeTelemetry = response;
          fetchNetworkTelemetry(tab.id, response);
        });
      }

      function fetchNetworkTelemetry(tabId, telemetry) {
        chrome.runtime.sendMessage({ action: "get_network_telemetry", tabId: tabId }, (netResponse) => {
          if (!chrome.runtime.lastError && netResponse) {
            telemetry.network = netResponse;
            updateNetworkTelemetry(netResponse);
          }
          updateDashboardTelemetry(telemetry);
        });
      }

      function updateNetworkTelemetry(net) {
        const setNet = (id, val) => {
          const el = document.getElementById(id);
          if (el) el.textContent = val;
        };
        setNet('net-requests', net.thirdPartyRequests || 0);
        setNet('net-domains', net.thirdPartyDomainsCount || 0);
        setNet('net-tracking', net.trackingScripts || 0);
        setNet('net-analytics', net.analyticsScripts || 0);
        setNet('net-ads', net.adScripts || 0);

        // Populate tracker domains with subdomain grouping
        const trackerList = document.getElementById('tracker-domains-list');
        const toggleBtn = document.getElementById('btn-toggle-trackers');
        const domainGroups = net.domainGroups || {};
        const groupKeys = Object.keys(domainGroups);

        const catColors = { analytics:'#d97706', advertising:'#ea580c', tracking:'#2563eb', other:'#6b7280' };
        const catLabels = { analytics:'Analytics', advertising:'Ad', tracking:'Tracking', other:'Other' };

        if (trackerList && toggleBtn) {
          if (groupKeys.length > 0) {
            toggleBtn.style.display = 'flex';
            let groupedHtml = '<div style="margin-bottom:4px;font-weight:600;font-size:10px;color:var(--text-main);">Domain Breakdown</div>';
            groupKeys.forEach(mainDomain => {
              const group = domainGroups[mainDomain];
              const subKeys = Object.keys(group.subdomains);
              groupedHtml += '<div style="margin:4px 0;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">' +
                '<div style="background:#f9fafb;padding:5px 8px;font-weight:600;font-size:10px;color:var(--text-main);display:flex;justify-content:space-between;align-items:center;">' +
                '<span>' + escapeHtml(mainDomain) + '</span>' +
                '<span style="font-weight:400;font-size:9px;color:var(--text-sub);">' + group.total + ' reqs</span>' +
                '</div>';
              subKeys.forEach(sub => {
                const info = group.subdomains[sub];
                const topCat = Object.keys(info.categories).reduce((a, b) => info.categories[a] > info.categories[b] ? a : b);
                const cc = catColors[topCat] || '#6b7280';
                const cl = catLabels[topCat] || 'Other';
                const subFull = sub + '.' + mainDomain;
                groupedHtml += '<div style="display:flex;align-items:center;gap:4px;padding:3px 8px;border-top:1px solid #f3f4f6;font-size:9px;color:var(--text-sub);">' +
                  '<span style="color:#9ca3af;">↳</span>' +
                  '<span style="font-family:monospace;color:#374151;flex:1;">' + escapeHtml(subFull) + '</span>' +
                  '<span style="background:' + cc + '15;color:' + cc + ';padding:1px 5px;border-radius:3px;font-size:8px;font-weight:600;white-space:nowrap;">' + cl + '</span>' +
                  '</div>';
              });
              groupedHtml += '</div>';
            });
            trackerList.innerHTML = groupedHtml;

            toggleBtn.onclick = function() {
              const isHidden = trackerList.style.display === 'none';
              trackerList.style.display = isHidden ? 'block' : 'none';
              this.classList.toggle('expanded', isHidden);
              document.getElementById('btn-toggle-trackers-text').textContent = isHidden ? 'Hide Domain Breakdown' : 'View Domain Breakdown';
            };
          } else {
            toggleBtn.style.display = 'none';
          }
        }
      }
      fetchDownloadProtectionStats();
    });
  }

  // Wire up Scan button click in header
  const btnHeaderScan = document.getElementById('btn-header-scan');
  if (btnHeaderScan) {
    btnHeaderScan.addEventListener('click', () => {
      triggerScan();
    });
  }

  // Wire up Analyze Current Page button in Safe dashboard
  const btnAnalyzeNow = document.getElementById('btn-analyze-now');
  if (btnAnalyzeNow) {
    btnAnalyzeNow.addEventListener('click', () => {
      triggerScan();
    });
  }

  // Wire up Go Back to Safety button
  const btnBackSafety = document.getElementById('btn-back-safety');
  if (btnBackSafety) {
    btnBackSafety.addEventListener('click', () => {
      if (activeTabInfo) {
        chrome.tabs.goBack(activeTabInfo.id, () => {
          if (chrome.runtime.lastError) {
            chrome.tabs.update(activeTabInfo.id, { url: 'chrome://newtab/' });
          }
          window.close();
        });
      } else {
        window.close();
      }
    });
  }

  // Wire up Proceed Anyway button
  const btnProceedAnyway = document.getElementById('btn-proceed-anyway');
  if (btnProceedAnyway) {
    btnProceedAnyway.addEventListener('click', () => {
      window.close();
    });
  }

  // Wire up search input in history tab
  const inputSearchHistory = document.getElementById('input-search-history');
  if (inputSearchHistory) {
    inputSearchHistory.addEventListener('input', (e) => {
      filterHistory(e.target.value);
    });
  }

  // Wire up Reset link
  const btnResetFactory = document.getElementById('btn-reset-factory');
  if (btnResetFactory) {
    btnResetFactory.addEventListener('click', () => {
      if (confirm('Are you sure you want to reset Site Sentinel history and settings to defaults?')) {
        localStorage.removeItem('sitesentinel_history');
        localStorage.removeItem('sitesentinel_settings');
        initSettings();
        initHistory();
      }
    });
  }

  // Wire up View History link in Dashboard
  const linkViewHistory = document.getElementById('link-view-history');
  if (linkViewHistory) {
    linkViewHistory.addEventListener('click', (e) => {
      e.preventDefault();
      switchTab('history');
    });
  }

  // Wire up Export History button
  const btnExport = document.getElementById('btn-export-history');
  if (btnExport) {
    btnExport.addEventListener('click', exportHistory);
  }

  // Wire up Manage Shield button
  const btnShield = document.getElementById('btn-manage-shield');
  if (btnShield) {
    btnShield.addEventListener('click', () => {
      switchTab('settings');
    });
  }

  // Helper: Trigger the full scan (with animation + overlay)
  function triggerScan() {
    if (!activeTabInfo && typeof chrome === 'undefined') return;

    const overlay = document.getElementById('scan-loading-overlay');
    if (overlay) overlay.classList.remove('hidden');

    const step1 = document.getElementById('load-step-1');
    const step2 = document.getElementById('load-step-2');
    const step3 = document.getElementById('load-step-3');

    setStepState(step1, 'active');
    setStepState(step2, 'pending');
    setStepState(step3, 'pending');

    // Refresh network telemetry for fresh tracker data
    function doScan() {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ action: 'get_network_telemetry', tabId: activeTabInfo.id }, (netResponse) => {
          if (!chrome.runtime.lastError && netResponse && activeTelemetry) {
            activeTelemetry.network = netResponse;
            updateNetworkTelemetry(netResponse);
          }
          captureAndProceed();
        });
      } else {
        captureAndProceed();
      }
    }

    function captureAndProceed() {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
          action: 'capture_screenshot',
          windowId: activeTabInfo && activeTabInfo.windowId
        }, (screenshotResp) => {
          if (chrome.runtime.lastError || !screenshotResp || screenshotResp.error) {
            proceedWithAnalysis(null);
            return;
          }
          proceedWithAnalysis(screenshotResp.screenshot || null);
        });
      } else {
        proceedWithAnalysis(null);
      }
    }

    function proceedWithAnalysis(screenshotData) {
      setStepState(step1, 'completed');
      setStepState(step2, 'active');

      setTimeout(() => {
        setStepState(step2, 'completed');
        setStepState(step3, 'active');

        sendAnalysisData(activeTelemetry, screenshotData, (result) => {
          setStepState(step3, 'completed');

          setTimeout(() => {
            if (overlay) overlay.classList.add('hidden');
            renderScanResult(result);
          }, 400);
        });
      }, 600);
    }

    doScan();
  }

  function setStepState(element, state) {
    if (!element) return;
    element.classList.remove('active', 'completed');
    if (state === 'active') element.classList.add('active');
    if (state === 'completed') element.classList.add('completed');
  }

  function computeLocalScore(telemetry) {
    let risk = 0;
    const flags = [];
    const trust = telemetry.trust || {};
    const links = telemetry.links || {};
    const dataFields = telemetry.dataFields || {};
    const security = telemetry.security || {};
    const hidden = telemetry.hiddenElements || {};
    const net = telemetry.network || {};

    if (!trust.isHttps) {
      risk += 30;
      flags.push("Site is not using HTTPS (unencrypted connection)");
    }
    if (!trust.hasPrivacyPolicy) {
      risk += 15;
      flags.push("No privacy policy link found");
    }
    if (!trust.hasTerms) {
      risk += 10;
      flags.push("No terms & conditions link found");
    }
    if (!trust.hasContact) {
      risk += 5;
      flags.push("No contact or support page found");
    }
    if (telemetry.externalFormActions > 0) {
      risk += 35;
      flags.push("Form(s) submit data to an external domain");
    }

    const suspiciousFormActions = telemetry.suspiciousFormActions || [];
    if (suspiciousFormActions.length > 0) {
      risk += 25;
      flags.push("Suspicious form action URLs detected (" + suspiciousFormActions.length + ")");
    }

    if (telemetry.loginForms > 0 && !trust.isHttps) {
      risk += 20;
      flags.push("Login form on insecure (non-HTTPS) page");
    }

    // Enhanced keyword scoring by category
    const keywordCategories = telemetry.keywordCategories || {};
    const catWeights = { phishing: 35, credential_theft: 30, scam: 25, malware: 40, social_engineering: 25, financial: 20, urgency: 10 };
    if (Object.keys(keywordCategories).length > 0) {
      let totalCatScore = 0;
      const catFlags = [];
      for (const [cat, data] of Object.entries(keywordCategories)) {
        const weight = catWeights[cat] || 15;
        const catScore = Math.min(data.count * (weight / 3), weight);
        totalCatScore += catScore;
        catFlags.push(cat.replace(/_/g, ' ') + " (" + data.count + ")");
      }
      risk += Math.min(totalCatScore, 50);
      flags.push("Threat categories: " + catFlags.join(", "));
    }

    const keywordTotalSeverity = telemetry.keywordTotalSeverity || 0;
    const keywords = telemetry.detectedKeywords || [];
    if (keywordTotalSeverity > 0) {
      risk += Math.min(keywordTotalSeverity * 2, 30);
    } else if (keywords.length > 0 && Object.keys(keywordCategories).length === 0) {
      risk += Math.min(keywords.length * 10, 25);
      flags.push("Suspicious keywords detected: " + keywords.slice(0, 5).join(', '));
    }

    const shortened = links.shortenedUrls || 0;
    if (shortened > 0) {
      risk += Math.min(shortened * 10, 20);
      flags.push("Shortened URLs found (destination hidden)");
    }

    const suspiciousLinks = links.suspiciousExternalLinks || [];
    if (suspiciousLinks.length > 0) {
      risk += Math.min(suspiciousLinks.length * 8, 25);
      flags.push("Suspicious external links detected (" + suspiciousLinks.length + ")");
    }

    const lowCredLinks = links.lowCredibilityLinks || [];
    if (lowCredLinks.length > 0) {
      risk += Math.min(lowCredLinks.length * 5, 15);
      flags.push("Low-credibility TLD links (" + lowCredLinks.length + ")");
    }

    const cardFields = dataFields.creditCardFields || 0;
    if (cardFields > 0) {
      risk += 10;
      flags.push("Credit card input fields detected");
    }
    if ((telemetry.loginForms || 0) > 0 && (telemetry.passwordFields || 0) > 3) {
      risk += 10;
      flags.push("Multiple password fields detected");
    }
    const externalLinks = links.externalLinks || 0;
    const internalLinks = links.internalLinks || 0;
    const totalLinks = externalLinks + internalLinks;
    if (totalLinks > 0 && (externalLinks / totalLinks) > 0.8) {
      risk += 15;
      flags.push("High external link ratio");
    }
    if ((telemetry.iframes || 0) > 3) {
      risk += 10;
      flags.push("High number of iframes detected");
    }

    if ((hidden.tinyIframes || 0) > 0) {
      risk += 15;
      flags.push("Tiny/hidden iframes detected (possible clickjacking)");
    }
    if ((hidden.hiddenInputs || 0) > 10) {
      risk += 5;
      flags.push("High number of hidden input fields (" + hidden.hiddenInputs + ")");
    }

    if (!security.hasCSP) {
      risk += 5;
      flags.push("Missing Content-Security-Policy");
    }

    const thirdPartyReqs = net.thirdPartyRequests || 0;
    if (thirdPartyReqs > 50) {
      risk += 20;
      flags.push("Excessive third-party requests (" + thirdPartyReqs + ")");
    } else if (thirdPartyReqs > 20) {
      risk += 10;
      flags.push("High number of third-party requests (" + thirdPartyReqs + ")");
    }
    if ((net.trackingScripts || 0) > 0) {
      risk += 15;
      flags.push("Tracking scripts detected (" + net.trackingScripts + ")");
    }
    if ((net.adScripts || 0) > 5) {
      risk += 10;
      flags.push("Multiple advertising scripts (" + net.adScripts + ")");
    }
    if ((net.analyticsScripts || 0) > 3) {
      risk += 5;
      flags.push("Multiple analytics scripts (" + net.analyticsScripts + ")");
    }

    risk = Math.min(risk, 100);
    const safety = 100 - risk;

    let verdict = 'safe';
    if (safety < 40) verdict = 'dangerous';
    else if (safety < 80) verdict = 'suspicious';

    const domain = telemetry.domain || telemetry.url || 'unknown';
    let summary = `Scanned ${domain}.`;
    if (flags.length > 0) {
      summary += ` Found ${flags.length} issue${flags.length > 1 ? 's' : ''}: ${flags.slice(0, 3).join('; ')}`;
      if (flags.length > 3) summary += ` and ${flags.length - 3} more.`;
    } else {
      summary += " No significant issues detected.";
    }

    return { safety, risk, verdict, flags, summary };
  }

  // Update dashboard cards with live telemetry data
  function updateDashboardTelemetry(telemetry) {
    if (!telemetry) return;

    const dataFields = telemetry.dataFields || {};
    const links = telemetry.links || {};
    const trust = telemetry.trust || {};
    const totalDataFields = (dataFields.nameFields || 0) + (dataFields.emailFields || 0) +
      (dataFields.phoneFields || 0) + (dataFields.addressFields || 0) +
      (dataFields.dobFields || 0) + (dataFields.creditCardFields || 0);

    // Data Fields card
    const labelFields = document.getElementById('label-data-fields');
    const pillFields = document.getElementById('pill-data-fields');
    const footerFields = document.getElementById('footer-data-fields');
    if (labelFields) labelFields.textContent = totalDataFields;
    if (pillFields) {
      if (dataFields.creditCardFields > 0) {
        pillFields.textContent = 'CC Detected!';
        pillFields.style.backgroundColor = '#fee2e2';
        pillFields.style.color = '#991b1b';
      } else if (totalDataFields > 0) {
        pillFields.textContent = totalDataFields + ' fields';
        pillFields.style.backgroundColor = '#ffedd5';
        pillFields.style.color = '#9a3412';
      } else {
        pillFields.textContent = 'No fields';
        pillFields.style.backgroundColor = '#f3f4f6';
        pillFields.style.color = '#4b5563';
      }
    }
    if (footerFields) {
      const fieldTypes = [];
      if (dataFields.nameFields > 0) fieldTypes.push('name');
      if (dataFields.emailFields > 0) fieldTypes.push('email');
      if (dataFields.phoneFields > 0) fieldTypes.push('phone');
      if (dataFields.addressFields > 0) fieldTypes.push('address');
      if (dataFields.creditCardFields > 0) fieldTypes.push('credit card');
      footerFields.textContent = fieldTypes.length > 0 ? fieldTypes.join(', ') : 'No personal data fields detected';
    }

    // External Links card
    const extLinks = links.externalLinks || 0;
    const intLinks = links.internalLinks || 0;
    const totalLinks = extLinks + intLinks;
    const labelExt = document.getElementById('label-ext-links');
    const fillExt = document.getElementById('fill-ext-ratio');
    const footerExt = document.getElementById('footer-ext-links');
    if (labelExt) labelExt.textContent = extLinks;
    if (fillExt && totalLinks > 0) {
      const ratio = Math.round((extLinks / totalLinks) * 100);
      fillExt.style.width = ratio + '%';
      if (ratio > 80) fillExt.style.backgroundColor = '#ef4444';
      else if (ratio > 50) fillExt.style.backgroundColor = '#f59e0b';
      else fillExt.style.backgroundColor = '#2563eb';
    }
    if (footerExt) {
      footerExt.textContent = totalLinks > 0 ? `${extLinks}/${totalLinks} links go off-domain` : 'No links detected';
    }

    // Trackers card
    const cookieCount = trust.cookieCount || 0;
    const scriptCount = telemetry.scriptCount || 0;
    const iframes = telemetry.iframes || 0;
    const trackersTotal = cookieCount + scriptCount + iframes;
    const labelTrackers = document.getElementById('label-trackers');
    const footerTrackers = document.getElementById('footer-trackers');
    const trackerTags = document.getElementById('tracker-tags');
    if (labelTrackers) labelTrackers.textContent = trackersTotal;
    if (footerTrackers) {
      footerTrackers.textContent = `${cookieCount} cookies, ${scriptCount} scripts, ${iframes} iframes`;
    }
    if (trackerTags) {
      const tags = [];
      if (cookieCount > 0) tags.push(cookieCount + ' cookies');
      if (iframes > 0) tags.push(iframes + ' iframes');
      trackerTags.innerHTML = tags.map(t => `<span class="mini-tag">${t}</span>`).join('');
    }

    // External Links Detail card
    updateExternalLinksDetail(telemetry);

    // Suspicious Links card
    updateSuspiciousLinks(telemetry);

    // Threat Categories card
    updateThreatCategories(telemetry);

    // Security Analysis card
    updateSecurityAnalysis(telemetry);

    // Hidden Elements card
    updateHiddenElements(telemetry);

    // Data Collection Summary card
    updateDataCollectionSummary(telemetry);

    // Permissions card
    updatePermissionsDisplay(telemetry);
  }

  function updateExternalLinksDetail(telemetry) {
    const container = document.getElementById('ext-links-list');
    if (!container) return;
    const links = telemetry.links || {};
    const extLinks = links.externalLinks || 0;
    const shortenedUrls = links.shortenedUrls || 0;
    const hasPrivacy = telemetry.trust && telemetry.trust.hasPrivacyPolicy;
    const hasTerms = telemetry.trust && telemetry.trust.hasTerms;
    const hasContact = telemetry.trust && telemetry.trust.hasContact;

    if (extLinks === 0 && shortenedUrls === 0) {
      container.innerHTML = 'No external links detected on this page.';
      return;
    }

    let html = '<div style="display:flex;flex-direction:column;gap:6px;">';
    html += `<div style="display:flex;justify-content:space-between;"><span>Total external links</span><span style="font-weight:700;">${extLinks}</span></div>`;
    if (shortenedUrls > 0) {
      html += `<div style="display:flex;justify-content:space-between;color:#b45309;"><span>Shortened URLs (hidden destination)</span><span style="font-weight:700;">${shortenedUrls}</span></div>`;
    }
    html += `<div style="display:flex;justify-content:space-between;"><span>Privacy policy link</span><span style="font-weight:700;color:${hasPrivacy ? '#10b981' : '#ef4444'};">${hasPrivacy ? 'Found' : 'Missing'}</span></div>`;
    html += `<div style="display:flex;justify-content:space-between;"><span>Terms & conditions</span><span style="font-weight:700;color:${hasTerms ? '#10b981' : '#ef4444'};">${hasTerms ? 'Found' : 'Missing'}</span></div>`;
    html += `<div style="display:flex;justify-content:space-between;"><span>Contact/Support page</span><span style="font-weight:700;color:${hasContact ? '#10b981' : '#ef4444'};">${hasContact ? 'Found' : 'Missing'}</span></div>`;
    html += '</div>';
    container.innerHTML = html;

    // Wire up external links toggle
    const extUrlList = document.getElementById('ext-urls-list');
    const extToggleBtn = document.getElementById('btn-toggle-ext-links');
    if (extToggleBtn) {
      extToggleBtn.onclick = function() {
        const isHidden = extUrlList.style.display === 'none';
        extUrlList.style.display = isHidden ? 'block' : 'none';
        this.classList.toggle('expanded', isHidden);
        document.getElementById('btn-toggle-ext-links-text').textContent = isHidden ? 'Hide Subdomain Breakdown' : 'View Subdomain Breakdown';
      };
    }

    // Populate external URL list with subdomain grouping
    const extUrlsDiv = document.getElementById('ext-urls-list');
    const extUrlsExpand = document.getElementById('ext-links-expand');
    const externalLinkDetails = (telemetry.links && telemetry.links.externalLinkDetails) || {};

    const purposeColors = { login:'#dc2626', payment:'#ea580c', download:'#2563eb', api:'#7c3aed', cdn:'#6b7280', social:'#3b82f6', analytics:'#d97706', advertising:'#ea580c', other:'#6b7280' };
    const purposeLabels = { login:'Login', payment:'Payment', download:'Download', api:'API', cdn:'CDN', social:'Social', analytics:'Analytics', advertising:'Ad', other:'Other' };

    if (extUrlsDiv && extUrlsExpand) {
      const detailKeys = Object.keys(externalLinkDetails);
      if (detailKeys.length > 0) {
        extUrlsExpand.style.display = 'block';
        let groupedHtml = '<div style="margin-bottom:6px;font-weight:600;font-size:10px;color:var(--text-main);">Subdomain Breakdown</div>';
        detailKeys.forEach(mainDomain => {
          const group = externalLinkDetails[mainDomain];
          groupedHtml += '<div style="margin:4px 0;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">' +
            '<div style="background:#f9fafb;padding:5px 8px;font-weight:600;font-size:10px;color:var(--text-main);display:flex;justify-content:space-between;align-items:center;">' +
            '<span>' + escapeHtml(mainDomain) + '</span>' +
            '<span style="font-weight:400;font-size:9px;color:var(--text-sub);">' + group.urls.length + ' link' + (group.urls.length !== 1 ? 's' : '') + '</span>' +
            '</div>';
          group.urls.forEach(item => {
            const pc = purposeColors[item.purpose] || '#6b7280';
            const pl = purposeLabels[item.purpose] || 'Other';
            groupedHtml += '<div style="display:flex;align-items:center;gap:4px;padding:3px 8px;border-top:1px solid #f3f4f6;font-size:9px;color:var(--text-sub);">' +
              '<span style="color:#9ca3af;">↳</span>' +
              '<span style="font-family:monospace;color:#374151;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(item.url) + '">' + escapeHtml(item.subdomain) + '.' + escapeHtml(mainDomain) + '</span>' +
              '<span style="background:' + pc + '15;color:' + pc + ';padding:1px 5px;border-radius:3px;font-size:8px;font-weight:600;white-space:nowrap;">' + pl + '</span>' +
              '</div>';
          });
          groupedHtml += '</div>';
        });
        extUrlsDiv.innerHTML = groupedHtml;
      } else {
        extUrlsExpand.style.display = 'none';
      }
    }
  }

  function updateSuspiciousLinks(telemetry) {
    const container = document.getElementById('suspicious-links-list');
    if (!container) return;
    const links = telemetry.links || {};
    const suspiciousLinks = links.suspiciousExternalLinks || [];
    const suspiciousDomains = links.suspiciousLinkDomains || [];

    if (suspiciousLinks.length === 0) {
      container.innerHTML = 'No suspicious external links detected.';
      return;
    }

    let html = '<div style="margin-bottom:6px;color:#b45309;font-weight:600;font-size:11px;">' +
      suspiciousLinks.length + ' suspicious link(s) — potential phishing destinations</div>';
    html += '<div style="max-height:120px;overflow-y:auto;">';
    suspiciousDomains.slice(0, 10).forEach(domain => {
      html += '<div style="padding:3px 0;font-size:9px;color:#991b1b;border-bottom:1px solid #fee2e2;">⚠ ' + escapeHtml(domain) + '</div>';
    });
    if (suspiciousDomains.length > 10) {
      html += '<div style="padding:3px 0;font-size:9px;color:var(--text-sub);">+' + (suspiciousDomains.length - 10) + ' more</div>';
    }
    html += '</div>';
    container.innerHTML = html;
  }

  function updateThreatCategories(telemetry) {
    const container = document.getElementById('threat-categories-list');
    if (!container) return;
    const categories = telemetry.keywordCategories || {};

    const catNames = {
      phishing: 'Phishing', credential_theft: 'Credential Theft', scam: 'Scam',
      malware: 'Malware', social_engineering: 'Social Engineering', financial: 'Financial',
      urgency: 'Urgency Tactics'
    };
    const catColors = {
      phishing: '#dc2626', credential_theft: '#dc2626', scam: '#ea580c',
      malware: '#b91c1c', social_engineering: '#d97706', financial: '#ca8a04',
      urgency: '#2563eb'
    };

    if (Object.keys(categories).length === 0) {
      container.innerHTML = 'No suspicious keywords detected.';
      return;
    }

    let html = '';
    for (const [cat, data] of Object.entries(categories)) {
      const color = catColors[cat] || '#6b7280';
      const name = catNames[cat] || cat.replace(/_/g, ' ');
      html += '<div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid #f1f5f9;">';
      html += '<div><span style="font-weight:600;color:' + color + ';">' + name + '</span>';
      html += '<span style="font-size:8px;color:var(--text-sub);margin-left:6px;">(' + data.keywords.slice(0, 2).map(function(kw) { return escapeHtml(kw); }).join(', ') + (data.keywords.length > 2 ? ', ...' : '') + ')</span></div>';
      html += '<div style="display:flex;align-items:center;gap:6px;">';
      html += '<span class="mini-tag" style="background:' + color + '20;color:' + color + ';">' + data.count + '</span>';
      html += '<span style="font-size:9px;color:var(--text-sub);">sev:' + data.maxSeverity + '</span>';
      html += '</div></div>';
    }
    container.innerHTML = html;
  }

  function updateSecurityAnalysis(telemetry) {
    const sec = telemetry.security || {};
    const hidden = telemetry.hiddenElements || {};

    const setSec = (id, val, color) => {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = val;
        if (color) el.style.color = color;
      }
    };

    setSec('sec-csp', sec.hasCSP ? 'Present' : 'Missing', sec.hasCSP ? '#10b981' : '#ef4444');
    setSec('sec-xframe', sec.hasXFrameOptions ? 'Present' : 'Missing', sec.hasXFrameOptions ? '#10b981' : '#ef4444');
    setSec('sec-hidden-iframes', (hidden.tinyIframes || 0) + (hidden.hiddenIframes || 0));
    setSec('sec-hidden-inputs', hidden.hiddenInputs || 0);
  }

  function updateHiddenElements(telemetry) {
    const hidden = telemetry.hiddenElements || {};

    const setHe = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setHe('he-tiny-iframes', (hidden.tinyIframes || 0) + (hidden.hiddenIframes || 0));
    setHe('he-hidden-inputs', hidden.hiddenInputs || 0);
    setHe('he-invisible', hidden.invisibleElements || 0);
  }

  function updateDataCollectionSummary(telemetry) {
    const dataFields = telemetry.dataFields || {};
    const setText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };
    setText('dc-forms', telemetry.formCount || 0);
    setText('dc-login', telemetry.loginForms || 0);
    setText('dc-password', telemetry.passwordFields || 0);
    setText('dc-email', dataFields.emailFields || 0);
    setText('dc-phone', dataFields.phoneFields || 0);
    setText('dc-cc', dataFields.creditCardFields || 0);
    setText('dc-iframes', telemetry.iframes || 0);

    // Highlight credit card fields if present
    const ccEl = document.getElementById('dc-cc');
    if (ccEl && (dataFields.creditCardFields || 0) > 0) {
      ccEl.style.color = '#ef4444';
    }
  }

  function updatePermissionsDisplay(telemetry) {
    const perms = telemetry.permissions || {};
    const setPerm = (id, value) => {
      const el = document.getElementById(id);
      if (el) {
        if (value === 'granted') {
          el.textContent = 'Granted';
          el.style.color = '#ef4444';
        } else if (value === 'prompt') {
          el.textContent = 'Prompt';
          el.style.color = '#f59e0b';
        } else {
          el.textContent = 'Denied';
          el.style.color = '#10b981';
        }
      }
    };
    setPerm('perm-geo', perms.geolocation);
    setPerm('perm-notif', perms.notifications);
    setPerm('perm-camera', perms.camera);
    setPerm('perm-mic', perms.microphone);
  }

  // Send request to FastAPI backend, with fallback to local analysis
  function sendAnalysisData(telemetry, screenshotBase64, callback) {
    const payload = { telemetry: telemetry || {} };
    if (screenshotBase64) {
      payload.screenshot = screenshotBase64.split(',')[1];
    }

    const domain = telemetry ? telemetry.domain : 'unknown-site.net';

    const controller = new AbortController();
    const timeoutId = setTimeout(function() { controller.abort(); }, 10000);

    fetch('http://127.0.0.1:8000/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    })
    .then(res => {
      clearTimeout(timeoutId);
      if (!res.ok) throw new Error('Status: ' + res.status);
      return res.json();
    })
    .then(data => {
      const result = {
        domain: domain,
        url: telemetry ? telemetry.url : '',
        score: data.ai_verdict ? data.ai_verdict.safety_score : 50,
        threatScore: data.ai_verdict ? 100 - data.ai_verdict.safety_score : 50,
        verdict: data.ai_verdict ? data.ai_verdict.verdict : 'suspicious',
        description: data.ai_verdict ? data.ai_verdict.summary : 'Anomalies detected in page analysis.',
        flags: data.ai_verdict ? data.ai_verdict.top_risks : []
      };
      callback(result);
    })
    .catch(err => {
      clearTimeout(timeoutId);
      console.warn('Backend unavailable, running local analysis:', err.message);
      const local = computeLocalScore(telemetry || {});
      const result = {
        domain: domain,
        url: telemetry ? telemetry.url : '',
        score: local.safety,
        threatScore: local.risk,
        verdict: local.verdict,
        description: local.summary,
        flags: local.flags
      };
      callback(result);
    });
  }

  // Display the result on the Dashboard tab
  function renderScanResult(result) {
    const dashboardSafe = document.getElementById('dashboard-safe');
    const dashboardRisk = document.getElementById('dashboard-risk');
    // Refresh dashboard telemetry cards with latest data
    if (activeTelemetry) {
      updateDashboardTelemetry(activeTelemetry);
    }

    // Save scan to history
    saveScanToHistory(result);
    updateRecentActivity(result);
    updateSecurityTip(result);
    fetchDownloadProtectionStats();

    if (result.verdict === 'safe') {
      if (dashboardSafe) dashboardSafe.classList.remove('hidden');
      if (dashboardRisk) dashboardRisk.classList.add('hidden');

      const safeDomainLabel = document.getElementById('safe-domain-label');
      if (safeDomainLabel) safeDomainLabel.textContent = result.domain;

      const safetyScoreLabel = document.getElementById('label-safety-score');
      if (safetyScoreLabel) safetyScoreLabel.textContent = result.score + '%';

      const fillSafetyScore = document.getElementById('fill-safety-score');
      if (fillSafetyScore) fillSafetyScore.style.width = result.score + '%';

      renderRiskBreakdownDetails(activeTelemetry);

    } else {
      if (dashboardSafe) dashboardSafe.classList.add('hidden');
      if (dashboardRisk) dashboardRisk.classList.remove('hidden');

      const threatVal = result.threatScore || (100 - result.score);
      const scoreValLabel = document.getElementById('risk-score-val');
      if (scoreValLabel) scoreValLabel.textContent = Math.round(threatVal) + '%';

      const riskDomainUrl = document.getElementById('risk-domain-url');
      if (riskDomainUrl) riskDomainUrl.textContent = result.url;

      animateRiskDial(threatVal);
      renderRiskFactors(result.flags);
      renderRiskBreakdownDetails(activeTelemetry);
    }
  }

  function renderRiskFactors(flags) {
    const container = document.getElementById('risk-factor-list');
    if (!container) return;
    if (!flags || flags.length === 0) {
      container.innerHTML = '<div style="font-size:10px;color:var(--text-sub);">No risk factors identified.</div>';
      return;
    }
    container.innerHTML = flags.map((flag, i) => {
      const severity = i < Math.ceil(flags.length / 3) ? 'critical' : 
                       i < Math.ceil(flags.length * 2 / 3) ? 'warning' : 'minor';
      const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);
      return `
        <div class="risk-factor-item">
          <div class="risk-factor-left">
            <div class="risk-icon-wrapper ${severity}">
              <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
              </svg>
            </div>
            <div class="risk-factor-details">
              <span class="risk-factor-name">Issue ${i + 1}</span>
              <span class="risk-factor-desc">${flag}</span>
            </div>
          </div>
          <span class="risk-badge ${severity}">${severityLabel}</span>
        </div>`;
    }).join('');
  }

  function renderRiskBreakdownDetails(telemetry) {
    const extCard = document.getElementById('card-risk-ext-links');
    const extContent = document.getElementById('risk-ext-links-content');
    const trackerCard = document.getElementById('card-risk-trackers');
    const trackerContent = document.getElementById('risk-trackers-content');

    // --- External Links Detail ---
    if (extCard && extContent) {
      const links = telemetry && telemetry.links || {};
      const details = links.externalLinkDetails || {};
      const extCount = links.externalLinks || 0;
      const detailKeys = Object.keys(details);

      if (extCount > 0 && detailKeys.length > 0) {
        extCard.classList.remove('hidden');
        const purposeColors = { login:'#dc2626', payment:'#ea580c', download:'#2563eb', api:'#7c3aed', cdn:'#6b7280', social:'#3b82f6', analytics:'#d97706', advertising:'#ea580c', other:'#6b7280' };
        const purposeLabels = { login:'Login', payment:'Payment', download:'Download', api:'API', cdn:'CDN', social:'Social', analytics:'Analytics', advertising:'Ad', other:'Other' };
        const shortUrls = links.shortenedUrls || 0;

        let html = '<div style="margin-bottom:6px;font-weight:600;font-size:10px;color:var(--text-main);">' + extCount + ' external link' + (extCount !== 1 ? 's' : '') + ' detected' +
          (shortUrls > 0 ? ' (' + shortUrls + ' shortened)' : '') + '</div>';

        detailKeys.forEach(mainDomain => {
          const group = details[mainDomain];
          html += '<div style="margin:4px 0;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">' +
            '<div style="background:#f9fafb;padding:5px 8px;font-weight:600;font-size:10px;color:var(--text-main);display:flex;justify-content:space-between;align-items:center;">' +
            '<span>' + escapeHtml(mainDomain) + '</span>' +
            '<span style="font-weight:400;font-size:9px;color:var(--text-sub);">' + group.urls.length + ' link' + (group.urls.length !== 1 ? 's' : '') + '</span>' +
            '</div>';
          group.urls.forEach(item => {
            const pc = purposeColors[item.purpose] || '#6b7280';
            const pl = purposeLabels[item.purpose] || 'Other';
            html += '<div style="display:flex;align-items:center;gap:4px;padding:3px 8px;border-top:1px solid #f3f4f6;font-size:9px;color:var(--text-sub);">' +
              '<span style="color:#9ca3af;">↳</span>' +
              '<span style="font-family:monospace;color:#374151;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(item.url) + '">' + escapeHtml(item.subdomain) + '.' + escapeHtml(mainDomain) + '</span>' +
              '<span style="background:' + pc + '15;color:' + pc + ';padding:1px 5px;border-radius:3px;font-size:8px;font-weight:600;white-space:nowrap;">' + pl + '</span>' +
              '</div>';
          });
          html += '</div>';
        });
        extContent.innerHTML = html;
      } else {
        extCard.classList.add('hidden');
      }
    }

    // --- Tracker Ranking ---
    if (trackerCard && trackerContent) {
      const net = telemetry && telemetry.network || {};
      const groups = net.domainGroups || {};
      const groupKeys = Object.keys(groups);

      if (groupKeys.length > 0) {
        trackerCard.classList.remove('hidden');

        const catSeverity = { tracking: 10, advertising: 8, analytics: 5, other: 2 };
        const catLabels = { analytics:'Analytics', advertising:'Ad', tracking:'Tracking', other:'Other' };
        const catColors = { analytics:'#d97706', advertising:'#ea580c', tracking:'#2563eb', other:'#6b7280' };

        // Rank domains: score = categorySeverity + min(count/5, 10) + subdomainBonus
        const ranked = groupKeys.map(main => {
          const g = groups[main];
          const subKeys = Object.keys(g.subdomains);
          let totalCatScore = 0;
          let maxCat = 'other';
          let maxCatCount = 0;
          let totalReqs = 0;
          subKeys.forEach(sub => {
            const info = g.subdomains[sub];
            totalReqs += info.count;
            Object.keys(info.categories).forEach(cat => {
              const c = info.categories[cat];
              if (c > maxCatCount) { maxCatCount = c; maxCat = cat; }
              totalCatScore += catSeverity[cat] || 2;
            });
          });
          const avgCatScore = subKeys.length > 0 ? totalCatScore / subKeys.length : 2;
          const reqBonus = Math.min(totalReqs / 3, 12);
          const subBonus = Math.min(subKeys.length * 3, 15);
          const score = Math.round(avgCatScore + reqBonus + subBonus);
          return { domain: main, score, subdomains: subKeys, totalReqs, topCat: maxCat };
        });

        ranked.sort((a, b) => b.score - a.score);

        const medalColors = ['#dc2626', '#d97706', '#6b7280'];
        const medalLabels = ['High Risk', 'Medium Risk', 'Low Risk'];

        let html = '<div style="margin-bottom:6px;font-weight:600;font-size:10px;color:var(--text-main);">' + groupKeys.length + ' tracker domain' + (groupKeys.length !== 1 ? 's' : '') + ' detected</div>';

        ranked.forEach((item, idx) => {
          const medal = idx < 3 ? medalColors[idx] : '#9ca3af';
          const badgeLabel = idx < 3 ? medalLabels[idx] : '';
          const cc = catColors[item.topCat] || '#6b7280';
          const cl = catLabels[item.topCat] || 'Other';

          html += '<div style="display:flex;align-items:center;gap:6px;padding:5px 6px;' + (idx > 0 ? 'border-top:1px solid #f3f4f6;' : '') + '">' +
            '<span style="width:18px;height:18px;border-radius:50%;background:' + medal + '20;color:' + medal + ';display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:700;flex-shrink:0;">' + (idx + 1) + '</span>' +
            '<div style="flex:1;min-width:0;">' +
            '<div style="display:flex;align-items:center;gap:4px;font-size:10px;font-weight:600;color:var(--text-main);">' +
            escapeHtml(item.domain) +
            '<span style="background:' + cc + '15;color:' + cc + ';padding:0 4px;border-radius:3px;font-size:8px;font-weight:600;">' + cl + '</span>' +
            '</div>' +
            '<div style="font-size:8px;color:var(--text-sub);margin-top:1px;">' +
            item.totalReqs + ' req' + (item.totalReqs !== 1 ? 's' : '') +
            ' · ' + item.subdomains.length + ' subdomain' + (item.subdomains.length !== 1 ? 's' : '') +
            ' · Score: ' + item.score +
            (badgeLabel ? ' · <span style="color:' + medal + ';font-weight:600;">' + badgeLabel + '</span>' : '') +
            '</div></div></div>';
        });
        trackerContent.innerHTML = html;
      } else {
        trackerCard.classList.add('hidden');
      }
    }
  }

  function animateRiskDial(threatPercent) {
    const circle = document.getElementById('risk-dial-circle');
    if (!circle) return;
    const circumference = 2 * Math.PI * 60;
    const offset = circumference - (threatPercent / 100) * circumference;
    circle.style.strokeDashoffset = offset;
  }

  function updateRecentActivity(result) {
    const container = document.getElementById('activity-list');
    if (!container) return;

    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const iconSvg = result.verdict === 'safe' ? `
      <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>` : `
      <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>`;

    const statusClass = result.verdict === 'safe' ? 'verified' : result.verdict === 'dangerous' ? 'blocked' : '';
    const statusLabel = result.verdict === 'safe' ? 'Verified' : result.verdict === 'dangerous' ? 'Blocked' : 'Suspicious';
    const iconBg = result.verdict !== 'safe' ? 'style="background-color: #fee2e2; color: #ef4444;"' : '';

    // Remove empty state
    const emptyMsg = container.querySelector('.activity-item[style*="center"]');
    if (emptyMsg) emptyMsg.remove();

    // Prepend new activity
    const item = document.createElement('div');
    item.className = 'activity-item';
    item.innerHTML = `
      <div class="activity-left">
        <div class="activity-icon-wrapper" ${iconBg}>
          ${iconSvg}
        </div>
        <div class="activity-details">
          <span class="activity-domain">${escapeHtml(result.domain)}</span>
          <span class="activity-category">Safety: ${result.score}%</span>
        </div>
      </div>
      <div class="activity-right">
        <span class="status-pill ${statusClass}">${statusLabel}</span>
        <span class="activity-time">${timeStr}</span>
      </div>`;
    container.insertBefore(item, container.firstChild);

    // Keep max 5 items
    while (container.children.length > 5) {
      container.removeChild(container.lastChild);
    }
  }

  function updateSecurityTip(result) {
    const tipEl = document.getElementById('security-tip-text');
    if (!tipEl) return;
    const tips = [
      "Enable 2FA on all your critical accounts for an extra layer of security.",
      "Avoid clicking links in unsolicited emails. Always verify the sender first.",
      "Use a password manager to generate and store unique passwords.",
      "Keep your browser and extensions updated to patch security vulnerabilities.",
      "Be cautious of sites requesting excessive personal information.",
      "Check for HTTPS (lock icon) before entering sensitive data on any website.",
      "Regularly review app permissions and revoke access for unused services.",
      "Shortened URLs can hide malicious destinations. Expand them before clicking."
    ];
    const idx = Math.floor(Math.random() * tips.length);
    tipEl.textContent = tips[idx];
  }

  // Tab switching logic
  function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const searchBtn = document.getElementById('btn-header-search');
    const scanBtn = document.getElementById('btn-header-scan');

    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        switchTab(targetTab);
      });
    });
  }

  function switchTab(tabId) {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const searchBtn = document.getElementById('btn-header-search');
    const scanBtn = document.getElementById('btn-header-scan');

    // Update active tab buttons
    tabButtons.forEach(b => {
      if (b.getAttribute('data-tab') === tabId) {
        b.classList.add('active');
      } else {
        b.classList.remove('active');
      }
    });

    // Update active tab contents
    tabContents.forEach(c => {
      if (c.getAttribute('id') === 'tab-' + tabId) {
        c.classList.add('active');
      } else {
        c.classList.remove('active');
      }
    });

    // Header updates
    if (tabId === 'history') {
      if (scanBtn) scanBtn.classList.add('hidden');
      if (searchBtn) searchBtn.classList.remove('hidden');
    } else {
      if (scanBtn) scanBtn.classList.remove('hidden');
      if (searchBtn) searchBtn.classList.add('hidden');
    }
  }

  // Settings tab handlers
  function initSettings() {
    const defaultSettings = {
      realtime: true,
      email: true,
      notifications: false,
      dataCollection: true,
      downloadProtection: true,
      whitelist: []
    };

    let settings = defaultSettings;
    try {
      const stored = localStorage.getItem('sitesentinel_settings');
      if (stored) settings = JSON.parse(stored);
    } catch (_) {}

    if (!settings.whitelist) settings.whitelist = [];

    const toggleRealtime = document.getElementById('toggle-realtime');
    const toggleEmail = document.getElementById('toggle-email');
    const toggleNotifications = document.getElementById('toggle-notifications');
    const toggleDataCollection = document.getElementById('toggle-data-collection');

    if (toggleRealtime) {
      toggleRealtime.checked = settings.realtime;
      toggleRealtime.addEventListener('change', (e) => {
        settings.realtime = e.target.checked;
        saveSettings(settings);
        // Sync with chrome.storage for background.js
        if (typeof chrome !== 'undefined' && chrome.storage) {
          chrome.storage.local.set({ sitesentinel_settings: settings });
        }
      });
    }

    if (toggleEmail) {
      toggleEmail.checked = settings.email;
      toggleEmail.addEventListener('change', (e) => {
        settings.email = e.target.checked;
        saveSettings(settings);
      });
    }

    if (toggleNotifications) {
      toggleNotifications.checked = settings.notifications;
      toggleNotifications.addEventListener('change', (e) => {
        settings.notifications = e.target.checked;
        saveSettings(settings);
      });
    }

    if (toggleDataCollection) {
      toggleDataCollection.checked = settings.dataCollection;
      toggleDataCollection.addEventListener('change', (e) => {
        settings.dataCollection = e.target.checked;
        saveSettings(settings);
      });
    }

    const toggleDownloadProtection = document.getElementById('toggle-download-protection');
    if (toggleDownloadProtection) {
      toggleDownloadProtection.checked = settings.downloadProtection;
      toggleDownloadProtection.addEventListener('change', (e) => {
        settings.downloadProtection = e.target.checked;
        saveSettings(settings);
        if (typeof chrome !== 'undefined' && chrome.runtime) {
          chrome.runtime.sendMessage({ action: 'set_download_protection', enabled: e.target.checked });
        }
        if (e.target.checked) {
          document.getElementById('dp-status').textContent = 'Active';
          document.getElementById('dp-status').style.cssText = 'font-size:9px;font-weight:700;padding:3px 8px;border-radius:10px;background:#dcfce7;color:#166534;';
        } else {
          document.getElementById('dp-status').textContent = 'Off';
          document.getElementById('dp-status').style.cssText = 'font-size:9px;font-weight:700;padding:3px 8px;border-radius:10px;background:#f3f4f6;color:#6b7280;';
        }
      });
    }

    // Whitelist management
    renderWhitelist(settings.whitelist);

    const whitelistInput = document.getElementById('input-whitelist-domain');
    const addBtn = document.getElementById('btn-add-whitelist');

    if (addBtn && whitelistInput) {
      addBtn.addEventListener('click', () => {
        let domain = whitelistInput.value.trim().toLowerCase();
        if (!domain) return;
        // Strip protocol and path
        try {
          if (domain.includes('://')) {
            domain = new URL(domain).hostname;
          }
        } catch (e) {}
        domain = domain.replace(/^www\./, '');

        if (!settings.whitelist.includes(domain)) {
          settings.whitelist.push(domain);
          saveSettings(settings);
          if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.set({ sitesentinel_settings: settings });
          }
          renderWhitelist(settings.whitelist);
        }
        whitelistInput.value = '';
      });

      whitelistInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') addBtn.click();
      });
    }

    // Update Check Button
    const btnCheckUpdates = document.getElementById('btn-check-updates');
    if (btnCheckUpdates) {
      btnCheckUpdates.addEventListener('click', () => {
        btnCheckUpdates.textContent = 'Checking...';
        btnCheckUpdates.disabled = true;
        setTimeout(() => {
          btnCheckUpdates.innerHTML = 'Updated!';
          btnCheckUpdates.disabled = false;
          setTimeout(() => {
            btnCheckUpdates.innerHTML = 'Check for Updates';
          }, 2000);
        }, 1000);
      });
    }
  }

  function renderWhitelist(whitelist) {
    const container = document.getElementById('whitelist-domains');
    if (!container) return;

    if (!whitelist || whitelist.length === 0) {
      container.innerHTML = '<div style="color:var(--text-sub);">No trusted sites added.</div>';
      return;
    }

    container.innerHTML = whitelist.map(domain =>
      '<div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid #f1f5f9;">' +
      '<span style="font-weight:600;color:var(--text-main);font-size:11px;">' + escapeHtml(domain) + '</span>' +
      '<button class="remove-whitelist-btn" data-domain="' + escapeHtml(domain) + '" style="background:none;border:none;color:#ef4444;font-size:14px;font-weight:700;cursor:pointer;padding:2px 6px;">&times;</button>' +
      '</div>'
    ).join('');

    container.querySelectorAll('.remove-whitelist-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const domain = btn.getAttribute('data-domain');
        const filtered = whitelist.filter(function(d) { return d !== domain; });
        const updated = { whitelist: filtered };
        try {
          const stored = localStorage.getItem('sitesentinel_settings');
          if (stored) {
            const s = JSON.parse(stored);
            s.whitelist = filtered;
            localStorage.setItem('sitesentinel_settings', JSON.stringify(s));
            if (typeof chrome !== 'undefined' && chrome.storage) {
              chrome.storage.local.set({ sitesentinel_settings: s });
            }
          } else {
            localStorage.setItem('sitesentinel_settings', JSON.stringify(updated));
          }
        } catch (_) {}
        renderWhitelist(filtered);
      });
    });
  }

  function saveSettings(settings) {
    localStorage.setItem('sitesentinel_settings', JSON.stringify(settings));
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set({ sitesentinel_settings: settings });
    }
  }

  function wireupSettingsLinks() {
    const linkAbout = document.getElementById('link-about');
    if (linkAbout) {
      linkAbout.addEventListener('click', (e) => {
        e.preventDefault();
        if (typeof chrome !== 'undefined' && chrome.tabs) {
          chrome.tabs.create({ url: 'https://chrome.google.com/webstore/category/extensions' });
        }
      });
    }

    const linkFalsePositive = document.getElementById('link-false-positive');
    if (linkFalsePositive) {
      linkFalsePositive.addEventListener('click', (e) => {
        e.preventDefault();
        if (typeof chrome !== 'undefined' && chrome.tabs) {
          chrome.tabs.create({ url: 'https://github.com' });
        }
      });
    }

    const linkPrivacy = document.getElementById('link-privacy');
    if (linkPrivacy) {
      linkPrivacy.addEventListener('click', (e) => {
        e.preventDefault();
        if (typeof chrome !== 'undefined' && chrome.tabs) {
          chrome.tabs.create({ url: 'https://www.privacytools.io' });
        }
      });
    }
  }

  function exportHistory() {
    let history = [];
    try {
      const stored = localStorage.getItem('sitesentinel_history');
      if (stored) history = JSON.parse(stored);
    } catch (_) {}

    if (history.length === 0) {
      return;
    }

    function csvEsc(val) { var s = String(val || ''); return '"' + s.replace(/"/g, '""') + '"'; }
    const csv = [
      'Domain,URL,Safety Score,Verdict,Date,Description',
      ...history.map(function(r) {
        return csvEsc(r.domain) + ',' + csvEsc(r.url) + ',' + (r.score != null ? r.score : '') + ',' + csvEsc(r.verdict) + ',' + csvEsc(r.dateStr) + ',' + csvEsc(r.description);
      })
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sitesentinel_history.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  // History tab handlers
  function initHistory() {
    let history = [];
    try {
      const stored = localStorage.getItem('sitesentinel_history');
      if (stored) history = JSON.parse(stored);
    } catch (_) {}

    renderHistoryList(history);
    updateHistorySummary(history);
  }

  function saveScanToHistory(scanResult) {
    let history = [];
    try {
      const stored = localStorage.getItem('sitesentinel_history');
      if (stored) history = JSON.parse(stored);
    } catch (_) {}

    const now = new Date();
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const timeStr = `${months[now.getMonth()]} ${now.getDate()}, ${now.getFullYear()} &bull; ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

    const newRecord = {
      domain: scanResult.domain,
      url: scanResult.url,
      score: scanResult.score,
      verdict: scanResult.verdict,
      dateStr: timeStr,
      description: scanResult.description,
      flags: scanResult.flags || [],
      threatScore: scanResult.threatScore || (100 - scanResult.score)
    };

    // Add to start of list
    history.unshift(newRecord);
    
    // Limit history length to 50 items
    if (history.length > 50) history.pop();

    localStorage.setItem('sitesentinel_history', JSON.stringify(history));
    
    // Re-render History lists
    renderHistoryList(history);
    updateHistorySummary(history);

    // Persist domain warning to chrome.storage for revisit detection
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['sitesentinel_domain_warnings'], (result) => {
        const warnings = result.sitesentinel_domain_warnings || {};
        warnings[scanResult.domain] = {
          verdict: scanResult.verdict,
          score: scanResult.score,
          threatScore: scanResult.threatScore || (100 - scanResult.score),
          url: scanResult.url,
          dateStr: timeStr,
          flags: scanResult.flags || [],
          description: scanResult.description
        };
        chrome.storage.local.set({ sitesentinel_domain_warnings: warnings });
      });
    }
  }

  function renderHistoryList(history) {
    const container = document.getElementById('list-past-scans');
    if (!container) return;

    container.innerHTML = '';

    if (history.length === 0) {
      container.innerHTML = '<div class="card" style="text-align:center;font-size:11px;color:var(--text-sub);">No scan history found.</div>';
      return;
    }

    history.forEach(item => {
      const card = document.createElement('div');
      card.className = 'history-card';
      card.setAttribute('data-domain', item.domain.toLowerCase());
      card.setAttribute('data-status', item.verdict);

      let iconClass = 'safe';
      let pillClass = 'verified';
      let verdictLabel = 'Safe';
      let svgIcon = `
        <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="20 6 9 17 4 12"></polyline>
        </svg>`;

      if (item.verdict === 'dangerous') {
        iconClass = 'malicious';
        pillClass = 'blocked';
        verdictLabel = 'Malicious';
        svgIcon = `
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>`;
      } else if (item.verdict === 'suspicious') {
        iconClass = 'suspicious';
        pillClass = 'warning';
        verdictLabel = 'Suspicious';
        svgIcon = `
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>`;
      }

      const truncatedDomain = item.domain.length > 22 ? item.domain.substring(0, 20) + '...' : item.domain;
      const statusPillStyle = item.verdict === 'suspicious' ? 'style="background-color: var(--yellow-bg); color: var(--yellow-text);"' : '';

      card.innerHTML = `
        <div class="history-card-header">
          <div class="history-card-left">
            <div class="history-card-icon ${iconClass}">
              ${svgIcon}
            </div>
            <div class="history-card-info">
              <span class="history-card-domain">${escapeHtml(truncatedDomain)}</span>
              <span class="history-card-date">${escapeHtml(item.dateStr)}</span>
            </div>
          </div>
          <span class="status-pill ${pillClass}" ${statusPillStyle}>${verdictLabel}</span>
        </div>
        <div class="history-card-desc">
          ${escapeHtml(item.description)}
        </div>
        <div class="history-card-actions">
          <button class="history-action-btn" title="View Full Report">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="16" x2="12" y2="12"></line>
              <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
          </button>
          <button class="history-action-btn" title="More Options">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="1"></circle>
              <circle cx="12" cy="5" r="1"></circle>
              <circle cx="12" cy="19" r="1"></circle>
            </svg>
          </button>
        </div>
      `;

      container.appendChild(card);
    });
  }

  function updateHistorySummary(history) {
    const maliciousCount = history.filter(item => item.verdict === 'dangerous').length;
    const suspiciousCount = history.filter(item => item.verdict === 'suspicious').length;
    const safeCount = history.filter(item => item.verdict === 'safe').length;
    const totalCount = history.length;

    const displayMalicious = maliciousCount;
    const displaySuspicious = suspiciousCount;
    const displaySafe = safeCount;
    const displayTotal = totalCount || 1;

    const totalEl = document.getElementById('hist-total-scanned');
    const maliciousEl = document.getElementById('hist-count-malicious');
    const suspiciousEl = document.getElementById('hist-count-suspicious');
    const safeEl = document.getElementById('hist-count-safe');

    if (totalEl) totalEl.textContent = totalCount.toLocaleString();
    if (maliciousEl) maliciousEl.textContent = displayMalicious.toLocaleString();
    if (suspiciousEl) suspiciousEl.textContent = displaySuspicious.toLocaleString();
    if (safeEl) safeEl.textContent = displaySafe.toLocaleString();

    const segmentMalicious = document.getElementById('segment-malicious');
    const segmentSuspicious = document.getElementById('segment-suspicious');
    const segmentSafe = document.getElementById('segment-safe');

    if (segmentMalicious && segmentSuspicious && segmentSafe) {
      const maliciousPercent = totalCount > 0 ? (displayMalicious / displayTotal) * 100 : 0;
      const suspiciousPercent = totalCount > 0 ? (displaySuspicious / displayTotal) * 100 : 0;
      const safePercent = totalCount > 0 ? (displaySafe / displayTotal) * 100 : 0;

      segmentMalicious.style.width = maliciousPercent + '%';
      segmentSuspicious.style.width = suspiciousPercent + '%';
      segmentSafe.style.width = safePercent + '%';
    }
  }

  function filterHistory(query) {
    const cards = document.querySelectorAll('.history-card');
    const lowerQuery = query.toLowerCase();

    cards.forEach(card => {
      const domain = card.getAttribute('data-domain') || '';
      const status = card.getAttribute('data-status') || '';
      const text = card.innerText.toLowerCase();

      if (domain.includes(lowerQuery) || status.includes(lowerQuery) || text.includes(lowerQuery)) {
        card.style.display = 'block';
      } else {
        card.style.display = 'none';
      }
    });
  }
});
