document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('target') || '';
  const risk = params.get('risk') || 'medium';
  const reason = params.get('reason') || 'Unknown reason';

  let domain = '';
  try { domain = new URL(targetUrl).hostname; } catch (e) {}

  document.getElementById('warning-domain').textContent = domain || 'this website';
  document.getElementById('warning-reason').textContent = reason;
  document.getElementById('warning-url').textContent = targetUrl;

  const riskBadge = document.getElementById('risk-badge');
  riskBadge.textContent = risk.toUpperCase();
  riskBadge.className = 'risk-badge ' + risk;

  const checkbox = document.getElementById('checkbox-dont-warn');

  chrome.tabs.getCurrent((tab) => {
    const tabId = tab ? tab.id : null;

    document.getElementById('btn-go-back').addEventListener('click', () => {
      window.close();
      setTimeout(() => {
        if (tabId != null) {
          chrome.tabs.goBack(tabId, () => {
            if (chrome.runtime.lastError) {
              chrome.tabs.update(tabId, { url: 'chrome://newtab/' });
            }
          });
        }
      }, 50);
    });

    document.getElementById('btn-proceed').addEventListener('click', () => {
      const dontWarn = checkbox.checked;

      const origin = (() => { try { return new URL(targetUrl).origin; } catch (_) { return targetUrl; } })();
      chrome.runtime.sendMessage({
        action: 'silence_url_warning',
        url: origin,
        domain: domain,
        dontWarn: dontWarn
      }, () => {
        if (tabId != null) {
          chrome.tabs.update(tabId, { url: targetUrl });
        } else {
          window.location.href = targetUrl;
        }
      });
    });
  });
});
