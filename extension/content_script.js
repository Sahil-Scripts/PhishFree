// content_script.js
(function () {
  "use strict";

  // ---------------------------
  // Utilities / metadata
  // ---------------------------
  function getVisibleText() {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode: (node) => {
        const txt = node.nodeValue ? node.nodeValue.trim() : "";
        if (!txt) return NodeFilter.FILTER_REJECT;
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        const tag = parent.tagName.toLowerCase();
        if (["script", "style", "noscript", "iframe"].includes(tag)) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    let chunks = [];
    let node;
    while ((node = walker.nextNode())) {
      chunks.push(node.nodeValue.trim());
      if (chunks.length >= 200) break;
    }
    let text = chunks.join(" ");
    if (text.length > 40000) text = text.slice(0, 40000);
    return text;
  }

  function getPageMeta() {
    return {
      title: document.title || "",
      url: window.location.href,
      hostname: window.location.hostname,
      metaDescription: (document.querySelector('meta[name="description"]') || {}).content || ""
    };
  }

  // ---------------------------
  // Session dismiss helpers
  // ---------------------------
  function sessionDismissed(hostname) {
    try {
      return sessionStorage.getItem("phishingproto.dismissed:" + hostname) === "1";
    } catch (e) {
      return false;
    }
  }
  function setSessionDismissed(hostname) {
    try {
      sessionStorage.setItem("phishingproto.dismissed:" + hostname, "1");
    } catch (e) { /* ignore */ }
  }

  // ---------------------------
  // Send to background for analysis
  // ---------------------------
  async function sendForAnalysis(trigger = "auto") {
    try {
      const payload = {
        url: window.location.href,
        hostname: window.location.hostname,
        title: document.title || "",
        meta_description: (document.querySelector('meta[name="description"]') || {}).content || "",
        text: getVisibleText(),
        trigger,
        timestamp: new Date().toISOString()
      };

      chrome.runtime.sendMessage({ action: "analyze_page", payload }, (response) => {
        if (response && response.result) {
          const result = response.result;

          // ALWAYS store the result so popup reads the latest analysis (even for low/benign).
          try {
            const storageObj = {};
            storageObj["analysis:" + window.location.href] = result;
            storageObj["last_analysis_for_current_tab"] = result;
            chrome.storage.local.set(storageObj, () => {
              console.debug("[content] stored analysis for", window.location.href);
            });
          } catch (e) {
            console.warn("[content] store failed:", e);
          }

          // don't show banner this session if user dismissed for this hostname
          if (sessionDismissed(window.location.hostname)) {
            removeBanner();
            return;
          }

          // show banner for all risk levels (low included)
          injectBanner(result);

        } else {
          console.warn("[content] analyze_page: no result returned", response);
        }
      });

    } catch (err) {
      console.error("content_script:failed", err);
    }
  }

  // ---------------------------
  // Message listener (re-analyze trigger)
  // ---------------------------
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    try {
      if (msg && msg.action === "trigger_reanalyze") {
        if (typeof sendForAnalysis === "function") {
          if (sessionDismissed(window.location.hostname) && msg.force !== true) {
            sendResponse({ ok: false, info: "dismissed_for_session" });
            return;
          }
          sendForAnalysis("manual");
          sendResponse({ ok: true, info: "reanalysis_triggered" });
        } else {
          sendResponse({ ok: false, error: "sendForAnalysis not available" });
        }
      }
    } catch (err) {
      console.error("content_script listener error:", err);
      sendResponse({ ok: false, error: String(err) });
    }
  });

  // ---------------------------
  // Explanation/threat helpers
  // ---------------------------
  function buildThreatPaths(result) {
    const threats = [];
    const reasons = (result.combined_reasons || result.reasons || (result.text && result.text.reasons) || []).map(r => String(r).toLowerCase());
    const components = (result.url && result.url.components) || {};
    const score = typeof result.aggregate_score === "number" ? result.aggregate_score : (result.score || 0);

    if (reasons.some(r => /login|verify|password|signin|confirm|account/.test(r)) ||
        (result.text && /password|account|login|verify|confirm/i.test(result.text.excerpt || "")) ||
        (result.text && result.text.suspicious && result.text.suspicious.length)) {
      threats.push("Credential theft — the page may try to trick you into entering your login & password (e.g. a fake 'LinkedIn' or 'bank' sign-in).");
    }

    if (reasons.some(r => /access.*file|drive|files|upload|permission/i.test(r)) ||
        (result.text && /access your (drive|files|photos|documents)/i.test(result.text.excerpt || ""))) {
      threats.push("Unauthorized data access — the site might try to access your files or cloud storage (e.g. 'Requests access to your Google Drive').");
    }

    if (reasons.some(r => /download|install|update|exe|apk/i.test(r)) ||
        (components && components.path && /download|install|setup|update/i.test(components.path))) {
      threats.push("Malware / unwanted download — the page may try to make you download malicious software (e.g. fake 'update' installers).");
    }

    if (reasons.some(r => /redirect|hop|shortener|bit\.ly|tinyurl|free-gifts|winner|prize/i.test(r)) ||
        (score >= 0.6 && reasons.length && reasons.some(r => /redirect|suspicious/))) {
      threats.push("Redirect-to-scam — you may be redirected to other fraudulent pages (e.g. fake payment pages or prize scams).");
    }

    if (reasons.some(r => /no https|http only|not secure|ssl/i.test(r)) || (components && components.has_https === false)) {
      threats.push("Connection interception risk — the page uses an insecure connection, which could expose data in transit.");
    }

    if (threats.length === 0 && score >= 0.6) {
      threats.push("High-risk behavior observed — likely phishing or fraud attempting to steal information or money.");
    }

    const out = [];
    for (const t of threats) {
      const key = t.toLowerCase();
      if (!out.find(x => x.toLowerCase() === key)) out.push(t);
      if (out.length >= 3) break;
    }
    return out;
  }

  function buildPlainExplanations(result) {
    const explanations = [];
    try {
      const threatPaths = buildThreatPaths(result);
      threatPaths.slice(0, 3).forEach(tp => explanations.push(tp));
    } catch (e) {
      console.error("buildPlainExplanations: threatPaths error", e);
    }

    const score = typeof result.aggregate_score === "number" ? result.aggregate_score : (result.score || (result.text && result.text.score) || null);
    if (score != null) {
      const pct = Math.round((parseFloat(score) || 0) * 100);
      explanations.push(`Overall risk: ${pct}%`);
    }

    const textReasons = (result.text && result.text.reasons) || result.reasons || result.reasons_text || result.combined_reasons || [];
    let tlist = [];
    if (Array.isArray(textReasons)) tlist = textReasons.map(String).filter(s => s && s.trim());
    else if (typeof textReasons === "string") tlist = [textReasons];

    tlist.slice(0, 3).forEach(r => {
      let rr = r;
      rr = rr.replace(/keyword[:\s]*/i, "Contains word:");
      rr = rr.replace(/transformer label[:\s]*/i, "Model label:");
      rr = rr.replace(/\b(verify|verification|verify your)\b/i, "Requests verification / account details");
      explanations.push(rr);
    });

    const components = (result.url && result.url.components) || (result.url && result.url.raw && result.url.raw.components) || null;
    if (components) {
      if (typeof components.redirect_count === "number" && components.redirect_count > 0) {
        explanations.push(`Redirects: ${components.redirect_count} hop(s)`);
      }
      if (components.has_https === false) explanations.push("Connection: No HTTPS (not secure)");
      else if (components.has_https === true) explanations.push("Connection: HTTPS (secure)");
      if (components.domain_age_days != null) {
        const d = components.domain_age_days;
        if (d < 30) explanations.push(`Domain age: ${d} days (very new)`);
        else if (d < 90) explanations.push(`Domain age: ${d} days (recent)`);
        else explanations.push(`Domain age: ${d} days`);
      } else if (!components.registrar) {
        explanations.push("Domain registration: unavailable");
      }
      if (components.registrar) explanations.push(`Registrar: ${components.registrar}`);
      if (components.asn_org) explanations.push(`Hosting: ${components.asn_org}`);
      else if (components.ip) explanations.push(`Server IP: ${components.ip}`);
    } else {
      const urlReasons = (result.url && result.url.reasons) || [];
      if (Array.isArray(urlReasons) && urlReasons.length) urlReasons.slice(0, 3).forEach(ur => explanations.push(String(ur)));
    }

    const dedup = [];
    for (const e of explanations) {
      const s = (e || "").toString().trim();
      if (!s) continue;
      if (!dedup.find(x => x.toLowerCase() === s.toLowerCase())) dedup.push(s);
      if (dedup.length >= 6) break;
    }
    return dedup;
  }

  function headlineAndAdvice(result) {
    const label = (result.label || result.risk_label || "").toString().toLowerCase();
    const score = typeof result.aggregate_score === "number" ? result.aggregate_score : (result.score || 0);
    const advice = { headline: "Unknown", short: "We couldn't determine risk.", className: "risk-unknown" };

    if (label === "high" || score >= 0.6) {
      advice.headline = "High Risk";
      advice.short = "This site looks dangerous — do not enter passwords or personal info.";
      advice.className = "risk-high";
    } else if (label === "medium" || score >= 0.35) {
      advice.headline = "Medium Risk";
      advice.short = "This site looks suspicious — double-check the URL and avoid sensitive input.";
      advice.className = "risk-medium";
    } else {
      advice.headline = "Low Risk";
      advice.short = "This site looks okay, but stay cautious.";
      advice.className = "risk-low";
    }
    return advice;
  }

  // Escape helper for inserted text
  function escapeHtml(s) {
    if (s == null) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // ---------------------------
  // Banner injection (updated)
  // ---------------------------
  const BANNER_AUTO_HIDE_MS = 15000; // 15s auto-hide default
  let _phishingproto_banner_timer = null;

  function injectBanner(result) {
    try {
      // Respect per-host session dismissal
      if (sessionDismissed(window.location.hostname)) {
        removeBanner();
        return;
      }

      // Remove existing banner & clear timer
      removeBanner();

      const advice = headlineAndAdvice(result);
      const bullets = buildPlainExplanations(result);
      if (!bullets.length) bullets.push("Suspicious signals detected (no detailed reasons available).");

      // create root banner
      const banner = document.createElement("div");
      banner.id = "phishingproto-banner";
      banner.setAttribute("role", "region");
      banner.setAttribute("aria-label", "Phishing warning from PhishingProto");
      banner.style.position = "fixed";
      banner.style.top = "0";
      banner.style.left = "0";
      banner.style.right = "0";
      banner.style.zIndex = "2147483647";
      banner.style.display = "flex";
      banner.style.justifyContent = "center";
      banner.style.pointerEvents = "auto";
      banner.style.transform = "translateY(-120%)";
      banner.style.transition = "transform 330ms cubic-bezier(.2,.9,.2,1)";
      banner.style.backdropFilter = "saturate(120%) blur(0.6px)";

      // wrapper (visual)
      const wrap = document.createElement("div");
      wrap.className = "phishingproto-wrap";
      wrap.style.width = "100%";
      wrap.style.maxWidth = "1600px";
      wrap.style.margin = "0 auto";
      wrap.style.display = "flex";
      wrap.style.alignItems = "flex-start";
      wrap.style.gap = "12px";
      wrap.style.padding = "14px 18px";
      wrap.style.boxSizing = "border-box";
      wrap.style.color = "#fff";
      wrap.style.boxShadow = "0 2px 6px rgba(0,0,0,0.2)";

      // typography improvements
      const fontStack = "'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif";
      banner.style.fontFamily = fontStack;
      banner.style.color = "#fff";
      banner.style.textRendering = "optimizeLegibility";
      banner.style.webkitFontSmoothing = "antialiased";
      banner.style.mozOsxFontSmoothing = "grayscale";
      wrap.style.fontFamily = fontStack;
      wrap.style.fontSize = "15px";
      wrap.style.lineHeight = "1.35";
      wrap.style.fontWeight = "500";

      // theme colors
      if (advice.className === "risk-high") {
        wrap.style.background = "linear-gradient(90deg,#7f1d1d,#b91c1c)";
      } else if (advice.className === "risk-medium") {
        wrap.style.background = "linear-gradient(90deg,#b45309,#f59e0b)";
      } else {
        wrap.style.background = "linear-gradient(90deg,#047857,#10b981)";
      }

      // Left: title + headline
      const left = document.createElement("div");
      left.style.minWidth = "220px";
      left.style.flex = "0 0 auto";
      left.innerHTML = `<div style="display:flex;align-items:center;gap:10px;">
                          <strong style="font-size:16px;font-weight:800">PhishingProto</strong>
                          <span style="background:rgba(255,255,255,0.08);padding:6px 8px;border-radius:8px;font-weight:700;font-size:12px">${escapeHtml(advice.headline)}</span>
                        </div>
                        <div style="margin-top:8px;font-size:13px;opacity:0.98">${escapeHtml(advice.short)}</div>`;

      // Center: bullets + "what you should do"
      const center = document.createElement("div");
      center.style.flex = "1 1 auto";
      center.style.padding = "0 14px";
      center.style.minWidth = "240px";

      const list = document.createElement("ul");
      list.className = "phishingproto-list";
      list.style.margin = "0";
      list.style.paddingLeft = "18px";
      list.style.listStyle = "disc";
      list.style.maxHeight = "220px";
      list.style.overflow = "auto";

      // initially show only first 2 bullets; rest collapsed
      bullets.forEach((b, i) => {
        const li = document.createElement("li");
        li.textContent = b;
        li.style.margin = "4px 0";
        if (i >= 2) li.dataset._extra = "1", li.style.display = "none";
        list.appendChild(li);
      });

      const expandToggle = document.createElement("button");
      expandToggle.textContent = bullets.length > 2 ? "View details" : "";
      expandToggle.style.marginTop = "8px";
      expandToggle.style.display = bullets.length > 2 ? "inline-block" : "none";
      expandToggle.style.background = "transparent";
      expandToggle.style.border = "1px solid rgba(255,255,255,0.12)";
      expandToggle.style.color = "#fff";
      expandToggle.style.padding = "6px 8px";
      expandToggle.style.borderRadius = "8px";
      expandToggle.style.cursor = "pointer";
      expandToggle.style.fontWeight = "700";

      expandToggle.addEventListener("click", () => {
        const showing = expandToggle.dataset.open === "1";
        const extras = list.querySelectorAll("li[data-_extra='1']");
        extras.forEach(e => e.style.display = showing ? "none" : "");
        expandToggle.textContent = showing ? "View details" : "Hide details";
        expandToggle.dataset.open = showing ? "0" : "1";
      });

      const what = document.createElement("div");
      what.style.marginTop = "8px";
      what.style.fontSize = "13px";
      what.style.opacity = "0.95";
      what.innerHTML = `<strong>What you should do:</strong> ${advice.headline === "High Risk" ? 'Don’t enter passwords or payment info. Close the tab if unsure.' : (advice.headline === "Medium Risk" ? 'Check the URL carefully, do not provide sensitive information.' : 'Proceed with normal caution.')}`;

      center.appendChild(list);
      center.appendChild(expandToggle);
      center.appendChild(what);

      // Right: actions
      const actions = document.createElement("div");
      actions.style.display = "flex";
      actions.style.flexDirection = "column";
      actions.style.gap = "8px";
      actions.style.minWidth = "160px";
      actions.style.alignItems = "flex-end";

      const detailsBtn = document.createElement("button");
      detailsBtn.className = "phishingproto-btn";
      detailsBtn.textContent = "Details";
      detailsBtn.style.padding = "8px 12px";
      detailsBtn.style.borderRadius = "8px";
      detailsBtn.style.border = "none";
      detailsBtn.style.cursor = "pointer";
      detailsBtn.style.background = "rgba(255,255,255,0.12)";
      detailsBtn.style.color = "#fff";
      detailsBtn.style.fontWeight = "700";
      detailsBtn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ action: "open_popup_for_url", url: window.location.href }, (resp) => {});
      });

      const reportBtn = document.createElement("button");
      reportBtn.className = "phishingproto-btn outline";
      reportBtn.textContent = "Report Safe";
      reportBtn.style.padding = "8px 12px";
      reportBtn.style.borderRadius = "8px";
      reportBtn.style.cursor = "pointer";
      reportBtn.style.background = "transparent";
      reportBtn.style.color = "#fff";
      reportBtn.style.border = "1px solid rgba(255,255,255,0.18)";
      reportBtn.style.fontWeight = "700";
      reportBtn.addEventListener("click", () => {
        try {
          reportBtn.disabled = true;
          reportBtn.textContent = "Reporting...";
          const payload = {
            url: window.location.href,
            hostname: window.location.hostname,
            timestamp: new Date().toISOString(),
            note: "reported_safe_by_user",
            analysis: result
          };
          chrome.runtime.sendMessage({ action: "report_false_positive", payload }, (resp) => {
            if (resp && resp.ok) {
              reportBtn.textContent = "Reported ✓";
              setTimeout(() => { reportBtn.textContent = "Report Safe"; }, 2500);
            } else {
              reportBtn.textContent = "Report Failed";
              setTimeout(() => { reportBtn.textContent = "Report Safe"; }, 2500);
            }
            reportBtn.disabled = false;
          });
        } catch (e) {
          console.error("report error", e);
          reportBtn.textContent = "Report failed";
          setTimeout(() => { reportBtn.textContent = "Report Safe"; }, 2500);
          reportBtn.disabled = false;
        }
      });

      const dismissBtn = document.createElement("button");
      dismissBtn.className = "phishingproto-btn outline small";
      dismissBtn.textContent = "Dismiss (this session)";
      dismissBtn.style.padding = "6px 8px";
      dismissBtn.style.borderRadius = "8px";
      dismissBtn.style.cursor = "pointer";
      dismissBtn.style.background = "transparent";
      dismissBtn.style.color = "#fff";
      dismissBtn.style.border = "1px solid rgba(255,255,255,0.18)";
      dismissBtn.style.fontWeight = "700";
      dismissBtn.addEventListener("click", () => {
        setSessionDismissed(window.location.hostname);
        removeBanner();
      });

      // Make buttons visually consistent
      [detailsBtn, reportBtn, dismissBtn, expandToggle].forEach(btn => {
        try {
          btn.style.fontFamily = fontStack;
          btn.style.fontWeight = "700";
          btn.style.fontSize = "14px";
        } catch (_) {}
      });

      actions.appendChild(detailsBtn);
      actions.appendChild(reportBtn);
      actions.appendChild(dismissBtn);

      wrap.appendChild(left);
      wrap.appendChild(center);
      wrap.appendChild(actions);

      banner.appendChild(wrap);

      // Insert at top of documentElement (fixed overlay), avoids layout shifts
      document.documentElement.prepend(banner);

      // trigger slide-in
      window.requestAnimationFrame(() => {
        banner.style.transform = "translateY(0)";
      });

      // Auto-hide behavior (clear any old timer)
      if (_phishingproto_banner_timer) {
        clearTimeout(_phishingproto_banner_timer);
        _phishingproto_banner_timer = null;
      }
      if (BANNER_AUTO_HIDE_MS > 0) {
        _phishingproto_banner_timer = setTimeout(() => {
          removeBanner();
        }, BANNER_AUTO_HIDE_MS);
      }

      // Pause auto-hide on hover or focus within banner
      banner.addEventListener("mouseenter", () => {
        if (_phishingproto_banner_timer) {
          clearTimeout(_phishingproto_banner_timer);
          _phishingproto_banner_timer = null;
        }
      });
      banner.addEventListener("mouseleave", () => {
        if (BANNER_AUTO_HIDE_MS > 0 && !_phishingproto_banner_timer) {
          _phishingproto_banner_timer = setTimeout(() => removeBanner(), BANNER_AUTO_HIDE_MS);
        }
      });

      // diagnostics marker
      try { sessionStorage.setItem("phishingproto.lastShown", window.location.href); } catch (e) { /* ignore */ }

    } catch (err) {
      console.error("injectBanner error", err);
    }
  }

  function removeBanner() {
    try {
      const existing = document.getElementById("phishingproto-banner");
      if (existing) {
        // animate out smoothly then remove
        existing.style.transform = "translateY(-120%)";
        if (_phishingproto_banner_timer) {
          clearTimeout(_phishingproto_banner_timer);
          _phishingproto_banner_timer = null;
        }
        // remove after animation time (match transition 330ms)
        setTimeout(() => {
          try { existing.remove(); } catch (e) {}
        }, 360);
      }
      if (window._phishingproto_banner_injected) delete window._phishingproto_banner_injected;
    } catch (e) {
      console.error("[content] removeBanner failed:", e);
    }
  }

  // ---------------------------
  // Auto-run only if user enabled preference (defaults to ON if not set)
  // ---------------------------
  (async function autoRunIfEnabled() {
    try {
      chrome.storage.local.get(["phishingproto_auto_analyze"], (items) => {
        const prefVal = items && Object.prototype.hasOwnProperty.call(items, "phishingproto_auto_analyze")
                         ? !!items.phishingproto_auto_analyze
                         : true;
        const enabled = prefVal;
        console.debug("[content] auto-analyze preference:", enabled);

        if (enabled) {
          let lastPath = location.pathname + location.search;
          if (!sessionDismissed(window.location.hostname)) sendForAnalysis("auto");

          window.addEventListener("popstate", () => {
            const newPath = location.pathname + location.search;
            if (newPath !== lastPath) {
              lastPath = newPath;
              if (!sessionDismissed(window.location.hostname)) sendForAnalysis("auto");
            }
          });

          const _push = history.pushState;
          history.pushState = function () {
            _push.apply(this, arguments);
            const np = location.pathname + location.search;
            if (np !== lastPath) {
              lastPath = np;
              if (!sessionDismissed(window.location.hostname)) sendForAnalysis("auto");
            }
          };
        } else {
          console.debug("content_script: auto-analyze disabled by user preference.");
        }
      });
    } catch (e) {
      console.error("content_script: auto-run check error", e);
    }
  })();

})();
