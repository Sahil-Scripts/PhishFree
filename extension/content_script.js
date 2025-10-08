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
  
  function siteReportedSafe(hostname) {
    try {
      return sessionStorage.getItem("phishingproto.reported_safe:" + hostname) === "1";
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
  // === NEW: Representative image extractor for CNN
  // Attempts to get a sensible image for CNN scoring:
  // - meta[property="og:image"]
  // - first same-origin <img> largest area
  // - data: URL images
  // - returns base64 data URI string or null
  // ---------------------------
  async function getRepresentativeImageBase64(maxWidth = 800) {
    try {
      // 1) og:image
      const og = document.querySelector('meta[property="og:image"], meta[name="og:image"]');
      if (og && og.content) {
        const url = og.content;
        const b64 = await fetchImageToDataUrl(url);
        if (b64) return b64;
      }

      // 2) find largest same-origin <img>
      const imgs = Array.from(document.images || []);
      // filter data: and same-origin images
      const candidates = imgs.filter(img => {
        if (!img || !img.src) return false;
        try {
          if (img.src.startsWith('data:')) return true;
          const srcUrl = new URL(img.src, window.location.href);
          return srcUrl.hostname === window.location.hostname;
        } catch (e) {
          return false;
        }
      });
      // sort by visible area (width*height)
      candidates.sort((a, b) => {
        const aw = (a.naturalWidth || a.width || 0);
        const ah = (a.naturalHeight || a.height || 0);
        const bw = (b.naturalWidth || b.width || 0);
        const bh = (b.naturalHeight || b.height || 0);
        return (bw * bh) - (aw * ah);
      });
      for (const img of candidates) {
        try {
          const b64 = await fetchImageToDataUrl(img.src);
          if (b64) return b64;
        } catch (e) { /* ignore and continue */ }
      }

      // 3) fallback: take a tiny screenshot of the page viewport using toDataURL via inpage canvas
      // NOTE: browsers restrict cross-origin content; this is a best-effort cheap fallback: draw some visible area if possible
      // We'll try to capture via HTMLCanvasElement.drawImage if an <svg> or same-origin image exists; otherwise skip.
      return null;
    } catch (e) {
      console.warn("getRepresentativeImageBase64 failed", e);
      return null;
    }
  }

  // Helper: fetch image bytes and return data:image/png;base64,... or data URL if it's already data:
  async function fetchImageToDataUrl(src) {
    try {
      if (!src) return null;
      if (src.startsWith("data:")) return src; // already a data URL
      const u = new URL(src, window.location.href);
      // Only allow same-origin fetch here for safety and to avoid CORS issues.
      if (u.hostname !== window.location.hostname && u.protocol.startsWith('http')) {
        // try to fetch via CORS — but silently skip if blocked
        // We'll attempt fetch once (server may allow CORS)
        try {
          const r = await fetch(u.href, { mode: 'cors' });
          if (!r.ok) return null;
          const blob = await r.blob();
          return await blobToDataUrl(blob);
        } catch (e) {
          return null;
        }
      } else {
        // same-origin — safe to fetch
        const r2 = await fetch(u.href);
        if (!r2.ok) return null;
        const blob = await r2.blob();
        return await blobToDataUrl(blob);
      }
    } catch (e) {
      return null;
    }
  }

  function blobToDataUrl(blob) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result);
      reader.onerror = () => resolve(null);
      reader.readAsDataURL(blob);
    });
  }

  // ---------------------------
  // Send to background for analysis
  // - includes text (LLM) and attempts to attach image_b64 (CNN) if available
  // - supports "run_models" array in payload (e.g. ["cnn","gnn"]) for targeted runs
  // ---------------------------
  async function sendForAnalysis(trigger = "auto", extra = {}) {
    try {
      const payload = {
        url: window.location.href,
        hostname: window.location.hostname,
        title: document.title || "",
        meta_description: (document.querySelector('meta[name="description"]') || {}).content || "",
        text: getVisibleText(),
        trigger,
        timestamp: new Date().toISOString(),
        // allow extra to include run_models etc.
        ...extra
      };

      // === NEW: attempt to attach representative image for CNN if backend asked or for manual triggers
      // Only fetch image if caller requested cnn or allowed image attachment
      // ALWAYS attempt to attach a representative image for CNN checks (best-effort)
try {
  const imgB64 = await getRepresentativeImageBase64();
  if (imgB64) {
    payload.image_b64 = imgB64;
    console.debug("[content] Attached image_b64 length:", payload.image_b64.length);
  } else {
    // no image found — still send domain/text
    console.debug("[content] No representative image found for this page");
  }
} catch (e) {
  console.warn("image attach failed", e);
}

// Ensure domain is present (GNN needs domain)
payload.domain = window.location.hostname || payload.hostname || "";

      console.debug("[content] sending analyze payload:", payload);
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
          sendForAnalysis("manual", { run_models: ["text","cnn","gnn"] });

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

    return threats;
  }

  function headlineAndAdvice(result) {
    const label = (result.label || result.risk_label || "").toString().toLowerCase();
    const score = typeof result.aggregate_score === "number" ? result.aggregate_score : (result.score || 0);
    const advice = { headline: "Unknown", short: "We couldn't determine risk.", className: "risk-unknown" };

    if (label === "high" || score >= 0.7) {
      advice.headline = "High Risk";
      advice.short = "This site looks dangerous — do not enter passwords or personal info.";
      advice.className = "risk-high";
    } else if (label === "medium" || score >= 0.4) {
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
      const reportedSafe = siteReportedSafe(window.location.hostname);
      
      // --- small inline model indicators (CNN / GNN) ---
let _cnn_pct = "—";
let _gnn_pct = "—";
try {
  const c = result.cnn_score ?? result.cnn_score_raw ?? (result.components_raw && result.components_raw.cnn) ?? (result.components && result.components.cnn);
  const g = result.gnn_score ?? result.gnn_score_raw ?? (result.components_raw && result.components_raw.gnn) ?? (result.components && result.components.gnn);
  function _norm(v) {
    if (v === undefined || v === null || v === "") return null;
    const n = Number(v);
    if (isNaN(n)) return null;
    if (n > 1 && n <= 100) return n / 100.0;
    if (n > 100) return Math.min(1, n / 100.0);
    return Math.max(0, Math.min(1, n));
  }
  const nc = _norm(c);
  const ng = _norm(g);
  if (nc !== null) _cnn_pct = `${Math.round(nc*100)}%`;
  if (ng !== null) _gnn_pct = `${Math.round(ng*100)}%`;
} catch (e) { /* ignore */ }

// We'll show these next to the title in a compact way by injecting small spans
const modelMini = `<div style="margin-left:8px;font-size:12px;opacity:0.95">
  <span style="margin-right:8px">Visual: <strong>${_cnn_pct}</strong></span>
  <span>Graph: <strong>${_gnn_pct}</strong></span>
</div>`;

// Add reported safe indicator
const safeIndicator = reportedSafe ? `<div style="margin-top:4px;font-size:12px;color:rgba(255,255,255,0.9);background:rgba(0,255,0,0.2);padding:2px 6px;border-radius:4px;display:inline-block;">✓ Reported Safe</div>` : '';

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
      banner.style.transition = "transform 330ms cubic-bezier(.2,9,2,1)";
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
                        ${modelMini}
                        ${safeIndicator}
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

      // === REPLACED expandToggle block: keeps original behavior and adds model details block
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

      // New: details block that shows model-specific fields (GNN / CNN) plus raw JSON
      const detailBox = document.createElement("details");
      detailBox.style.marginTop = "8px";
      const summary = document.createElement("summary");
      summary.textContent = "Show raw details (models)";
      summary.style.cursor = "pointer";
      summary.style.fontSize = "13px";
      summary.style.color = "rgba(255,255,255,0.92)";
      detailBox.appendChild(summary);

      // Build contents (GNN / CNN preferred fields)
      const modelsDiv = document.createElement("div");
      modelsDiv.style.marginTop = "8px";
      modelsDiv.style.fontSize = "13px";
      modelsDiv.style.color = "rgba(255,255,255,0.95)";
      try {
        // try to extract common keys - non-fatal if absent
        const gnnScore = result.gnn_score_raw ?? result.gnn_score ?? result.graph_score ?? result.score_raw ?? result.score;
        const gnnNeighbors = result.neighbors_found ?? result.gnn_neighbors ?? result.neighbors_count ?? result.neighbors;
        const cnnScore = result.cnn_score_raw ?? result.cnn_score ?? result.visual_score;
        const bestBrand = (result.cnn && result.cnn.best_brand) || result.best_brand || "";
        if (gnnScore !== undefined) {
          const p = document.createElement("div");
          p.textContent = `GNN score: ${String(gnnScore)}`;
          modelsDiv.appendChild(p);
        }
        if (gnnNeighbors !== undefined) {
          const p = document.createElement("div");
          p.textContent = `GNN neighbors: ${String(gnnNeighbors)}`;
          modelsDiv.appendChild(p);
        }
        if (cnnScore !== undefined) {
          const p = document.createElement("div");
          p.textContent = `CNN visual score: ${String(cnnScore)}`;
          modelsDiv.appendChild(p);
        }
        if (bestBrand) {
          const p = document.createElement("div");
          p.textContent = `CNN best match: ${String(bestBrand)}`;
          modelsDiv.appendChild(p);
        }
      } catch (e) {
        console.warn("banner model fields extract error", e);
      }

      // fallback: raw JSON viewer
      const rawPre = document.createElement("pre");
      rawPre.style.whiteSpace = "pre-wrap";
      rawPre.style.marginTop = "8px";
      rawPre.style.background = "rgba(255,255,255,0.05)";
      rawPre.style.padding = "8px";
      rawPre.style.borderRadius = "6px";
      try {
        rawPre.textContent = JSON.stringify(result, null, 2);
      } catch (e) {
        rawPre.textContent = String(result);
      }

      detailBox.appendChild(modelsDiv);
      detailBox.appendChild(rawPre);

      const what = document.createElement("div");
      what.style.marginTop = "8px";
      what.style.fontSize = "13px";
      what.style.opacity = "0.95";
      what.innerHTML = `<strong>What you should do:</strong> ${advice.headline === "High Risk" ? 'Don’t enter passwords or payment info. Close the tab if unsure.' : (advice.headline === "Medium Risk" ? 'Check the URL carefully, do not provide sensitive information.' : 'Proceed with normal caution.')}`;

      center.appendChild(list);
      center.appendChild(expandToggle);
      center.appendChild(detailBox);
      center.appendChild(what);

           // Right: actions
      const actions = document.createElement("div");
      actions.style.display = "flex";
      actions.style.flexDirection = "column";
      actions.style.gap = "8px";
      actions.style.minWidth = "160px";
      actions.style.alignItems = "flex-end";

      // Details button (existing behavior)
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
        console.debug("[content] detailsBtn clicked for", window.location.href);
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
          reportBtn.textContent = "Reporting.";
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
              // Store in session storage that this site was reported safe
              try {
                sessionStorage.setItem("phishingproto.reported_safe:" + window.location.hostname, "1");
              } catch (e) { /* ignore */ }
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

      // Append actions in logical order: Details, Report, Dismiss
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
  if (!sessionDismissed(window.location.hostname)) sendForAnalysis("auto", { run_models: ["text","cnn","gnn"] });

  window.addEventListener("popstate", () => {
    const newPath = location.pathname + location.search;
    if (newPath !== lastPath) {
      lastPath = newPath;
      if (!sessionDismissed(window.location.hostname)) sendForAnalysis("auto", { run_models: ["text","cnn","gnn"] });
    }
  });

  const _push = history.pushState;
  history.pushState = function () {
    _push.apply(this, arguments);
    const np = location.pathname + location.search;
    if (np !== lastPath) {
      lastPath = np;
      if (!sessionDismissed(window.location.hostname)) sendForAnalysis("auto", { run_models: ["text","cnn","gnn"] });
    }
  };
        }
 else {
          console.debug("content_script: auto-analyze disabled by user preference.");
        }
      });
    } catch (e) {
      console.error("content_script: auto-run check error", e);
    }
  })();

})();
