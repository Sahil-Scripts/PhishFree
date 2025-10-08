// popup.js - defensive version with better error handling & logs
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", () => {
    try {
      const status = document.getElementById("status");
      const resultDiv = document.getElementById("result");
      const noResult = document.getElementById("noResult");
      const badgeEmoji = document.getElementById("badgeEmoji");
      const labelText = document.getElementById("labelText");
      const scoreText = document.getElementById("scoreText");
      const reasonsList = document.getElementById("reasonsList");
      const rawJson = document.getElementById("rawJson");
      const riskMeterFill = document.getElementById("riskMeterFill");

      const reanalyzeBtn = document.getElementById("reanalyze");
      const detailsBtn = document.getElementById("detailsBtn");
      const detailsPanel = document.getElementById("detailsPanel");
      const closeDetails = document.getElementById("closeDetails");
      const detailUrl = document.getElementById("detailUrl");
      const detailText = document.getElementById("detailText");
      const detailReasons = document.getElementById("detailReasons");
      const openDashboardBtn = document.getElementById("openDashboard");
      const autoToggle = document.getElementById("autoAnalyzeToggle");
      const copyJsonBtn = document.getElementById("copyJsonBtn");
      const reportFpBtn = document.getElementById("reportFpBtn");
      const toast = document.getElementById("toast");

      const BACKEND = "http://127.0.0.1:5000";

      function log(...args) { console.debug("[popup]", ...args); }

      function showToast(message, duration = 3000) {
        if (!toast) return;
        toast.textContent = message;
        toast.classList.add("show");
        setTimeout(() => toast.classList.remove("show"), duration);
      }

      function safeSetText(el, txt) {
        if (!el) return;
        try { el.textContent = txt; } catch (e) { console.warn("safeSetText failed", e); }
      }

      function showNoResult(msg) {
        if (resultDiv) resultDiv.classList.add("hidden");
        if (noResult) {
          noResult.classList.remove("hidden");
          // don't replace entire element; change text child
          const p = noResult.querySelector("p");
          if (p) p.textContent = msg || "No analysis available yet.";
        }
        safeSetText(status, msg || "No analysis available yet.");
      }

      function formatLocalTimestamp(isoString) {
        try {
          if (!isoString) return new Date().toLocaleString();
          const d = new Date(isoString);
          return d.toLocaleString(undefined, { hour12: true, timeZoneName: "short" });
        } catch (e) {
          return isoString || "";
        }
      }

      function updateRiskMeter(score, label) {
        if (!riskMeterFill) return;
        const width = Math.min(Math.max(score * 100, 0), 100);
        riskMeterFill.style.width = `${width}%`;
        riskMeterFill.className = "risk-meter-fill";
        if (label) riskMeterFill.classList.add(label.toLowerCase());
      }

      function renderResult(json) {
        try {
          log("renderResult called", json);
          if (noResult) noResult.classList.add("hidden");
          if (resultDiv) resultDiv.classList.remove("hidden");

          const ts = json.timestamp || (json.text && json.text.timestamp) || new Date().toISOString();
          safeSetText(status, "Last analysis: " + formatLocalTimestamp(ts));
          safeSetText(badgeEmoji, json.badge || json.badgeEmoji || "");

          const label = (json.label || json.risk_label || "").toString();
          safeSetText(labelText, label ? label.toUpperCase() : "—");

          const score = (typeof json.aggregate_score !== "undefined") ? json.aggregate_score : (json.score || 0);
          safeSetText(scoreText, `Score: ${Number(score).toFixed(2)}`);

          updateRiskMeter(Number(score) || 0, label);

          if (reasonsList) {
            reasonsList.innerHTML = "";
            const reasons = json.combined_reasons || json.reasons || (json.text && json.text.reasons) || [];
            if (!reasons || reasons.length === 0) {
              const li = document.createElement("li");
              li.textContent = "No reasons provided.";
              reasonsList.appendChild(li);
            } else {
              reasons.forEach(r => {
                const li = document.createElement("li");
                li.textContent = r;
                reasonsList.appendChild(li);
              });
            }
          }

          if (rawJson) rawJson.textContent = JSON.stringify(json, null, 2);

          // Populate details
          if (detailUrl) detailUrl.textContent = (json.url && (json.url.raw || json.url.final_url || json.url.input_url)) || json.url || (json.text && json.text.source_url) || "—";
          if (detailText) {
            const excerpt = (json.text && json.text.components && json.text.components.excerpt) ||
                            (json.text && json.text.excerpt) ||
                            (json.text && json.text.raw_excerpt) ||
                            (json.input_text && json.input_text.slice ? json.input_text.slice(0, 600) : "") ||
                            "";
            detailText.textContent = excerpt || (json.text && json.text.raw ? json.text.raw.slice(0, 600) : "") || "—";
          }
          if (detailReasons) {
            detailReasons.innerHTML = "";
            const dr = json.combined_reasons || json.reasons || [];
            if (!dr || dr.length === 0) {
              const li = document.createElement("li");
              li.textContent = "No reasons provided.";
              detailReasons.appendChild(li);
            } else {
              dr.forEach(r => {
                const li = document.createElement("li");
                li.textContent = r;
                detailReasons.appendChild(li);
              });
            }
          }

          // --- populate CNN / GNN small indicators ---
          try {
            // helper to find first candidate key among shallow keys or nested objects
            function _findFirst(obj, keys) {
              if (!obj) return undefined;
              for (const k of keys) {
                if (obj[k] !== undefined && obj[k] !== null) return obj[k];
              }
              // shallow nested search
              for (const v of Object.values(obj)) {
                if (v && typeof v === 'object') {
                  for (const k of keys) {
                    if (v[k] !== undefined && v[k] !== null) return v[k];
                  }
                }
              }
              return undefined;
            }

            // CNN value candidates
            const candsC = [ 'cnn_score_raw','cnn_score','visual_score','score' ];
            // prefer top-level keys, then components_raw / components
            const cvalTop = _findFirst(json, candsC);
            const cvalCompRaw = (json.components_raw && json.components_raw.cnn) || (json.components && json.components.cnn);
            const cval = (cvalTop !== undefined ? cvalTop : cvalCompRaw);

            let cnum = 0;
            if (cval === undefined || cval === null || cval === "") {
              cnum = 0;
            } else if (typeof cval === 'number') {
              cnum = cval;
            } else {
              const parsed = parseFloat(String(cval).replace(/[^\d.-]/g, ''));
              cnum = isNaN(parsed) ? 0 : parsed;
            }

            let cnorm = cnum;
            if (cnorm > 1 && cnorm <= 100) cnorm = cnorm / 100.0;
            if (cnorm > 100) cnorm = Math.min(1, cnorm / 100.0);
            cnorm = isNaN(cnorm) ? 0 : cnorm;

            // GNN value candidates
            const candsG = [ 'gnn_score_raw','gnn_score','graph_score','similarity' ];
            const gvalTop = _findFirst(json, candsG);
            const gvalCompRaw = (json.components_raw && json.components_raw.gnn) || (json.components && json.components.gnn);
            const gval = (gvalTop !== undefined ? gvalTop : gvalCompRaw);

            let gnum = 0;
            if (gval === undefined || gval === null || gval === "") {
              gnum = 0;
            } else if (typeof gval === 'number') {
              gnum = gval;
            } else {
              const parsedG = parseFloat(String(gval).replace(/[^\d.-]/g, ''));
              gnum = isNaN(parsedG) ? 0 : parsedG;
            }

            let gnorm = gnum;
            if (gnorm > 1 && gnorm <= 100) gnorm = gnorm / 100.0;
            if (gnorm > 100) gnorm = Math.min(1, gnorm / 100.0);
            gnorm = isNaN(gnorm) ? 0 : gnorm;

            const cPct = Math.round(Math.max(0, Math.min(1, cnorm)) * 100);
            const gPct = Math.round(Math.max(0, Math.min(1, gnorm)) * 100);

            const popupCnnEl = document.getElementById('popup_cnn_pct');
            const popupCnnLabel = document.getElementById('popup_cnn_label');
            const popupGnnEl = document.getElementById('popup_gnn_pct');
            const popupGnnNeighbors = document.getElementById('popup_gnn_neighbors');

            if (popupCnnEl) popupCnnEl.textContent = cPct === 0 ? '—' : `${cPct}%`;
            if (popupCnnLabel) {
              if (cPct === 0) popupCnnLabel.textContent = 'No visual score';
              else if (cPct >= 75) popupCnnLabel.textContent = 'PHISH-LIKE';
              else if (cPct >= 40) popupCnnLabel.textContent = 'SUSPICIOUS';
              else popupCnnLabel.textContent = 'LIKELY SAFE';
            }

            if (popupGnnEl) popupGnnEl.textContent = gPct === 0 ? '—' : `${gPct}%`;
            const neigh = _findFirst(json, ['neighbors_found','gnn_neighbors','neighbors_count','neighbors','top_neighbors_count']) || 0;
            if (popupGnnNeighbors) popupGnnNeighbors.textContent = `Neighbors: ${neigh || 0}`;
          } catch (err) {
            console.warn('popup render model fields error', err);
          }

        } catch (err) {
          console.error("renderResult error:", err);
          safeSetText(status, "Error rendering result");
        }
      }

      // Wrapper to safely call chrome API
      function hasChromeApi(name) {
        try { return typeof chrome !== "undefined" && chrome[name]; } catch (e) { return false; }
      }

      function getActiveTab(callback) {
        try {
          if (!hasChromeApi("tabs")) {
            log("chrome.tabs not available.");
            return callback(null);
          }
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (!tabs || tabs.length === 0) return callback(null);
            callback(tabs[0]);
          });
        } catch (e) {
          console.error("getActiveTab exception:", e);
          callback(null);
        }
      }

      function loadAnalysisForTab(tab) {
        if (!tab || !tab.url) {
          showNoResult("No active tab or URL found.");
          return;
        }
        const key = "analysis:" + tab.url;
        try {
          if (!hasChromeApi("storage") || !chrome.storage || !chrome.storage.local) {
            showNoResult("No extension storage available.");
            return;
          }
          chrome.storage.local.get([key], (items) => {
            if (chrome.runtime && chrome.runtime.lastError) {
              console.error("storage.get error:", chrome.runtime.lastError);
              showNoResult("Storage access error");
              return;
            }
            const json = items ? items[key] : null;
            if (json) renderResult(json);
            else showNoResult("No analysis stored for this tab yet.");
          });
        } catch (e) {
          console.error("loadAnalysisForTab error:", e);
          showNoResult("Failed to load analysis for tab.");
        }
      }

      // Set up initial UI
      safeSetText(status, "Loading analysis for current tab...");
      getActiveTab((tab) => loadAnalysisForTab(tab));

      // Re-analyze button handler (robust fallback)
      if (reanalyzeBtn) {
        reanalyzeBtn.addEventListener("click", () => {
          getActiveTab(async (tab) => {
            if (!tab || !tab.url) {
              safeSetText(status, "No active tab to analyze.");
              return;
            }
            safeSetText(status, "Re-analyzing…");
            try {
              // First try content script trigger if available
              if (hasChromeApi("tabs") && hasChromeApi("runtime")) {
                chrome.tabs.sendMessage(tab.id, { action: "trigger_reanalyze" }, (resp) => {
                  // If there's an error (no content script), resp will be undefined and chrome.runtime.lastError set
                  if (chrome.runtime && chrome.runtime.lastError) {
                    log("sendMessage failed, falling back to backend:", chrome.runtime.lastError.message || chrome.runtime.lastError);
                    // fallback to backend
                    (async () => {
                      try {
                        const payload = { url: tab.url, title: tab.title || "", timestamp: new Date().toISOString() };
                        const respFetch = await fetch(BACKEND + "/analyze/aggregate", {
                          method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload)
                        });
                        if (!respFetch.ok) {
                          safeSetText(status, "Server error: " + respFetch.status);
                          return;
                        }
                        const json = await respFetch.json();
                        try {
                          chrome.storage.local.set({ ["analysis:" + tab.url]: json, ["tab:" + tab.id]: tab.url }, () => {
                            renderResult(json);
                            safeSetText(status, "Analysis saved locally.");
                            updateToolbarIcon(json.label || json.risk_label || "");
                          });
                        } catch (e) {
                          // if storage not available, just render
                          renderResult(json);
                          safeSetText(status, "Analysis received (no storage).");
                        }
                      } catch (err) {
                        console.error("Reanalyze fallback error:", err);
                        safeSetText(status, "Network error: is backend running?");
                      }
                    })();
                  } else {
                    // content script succeeded — wait a short bit for it to write results
                    setTimeout(() => {
                      try {
                        chrome.storage.local.get(["analysis:" + tab.url], (items) => {
                          const json = items ? items["analysis:" + tab.url] : null;
                          if (json) {
                            renderResult(json);
                            safeSetText(status, "Analysis updated.");
                            updateToolbarIcon(json.label || json.risk_label || "");
                          } else {
                            safeSetText(status, "No result returned yet.");
                          }
                        });
                      } catch (e) {
                        console.error("post-message storage fetch failed", e);
                      }
                    }, 900);
                  }
                });
              } else {
                // No chrome.tabs available (e.g., outside extension context) - do backend direct
                try {
                  const payload = { url: tab.url, title: tab.title || "", timestamp: new Date().toISOString() };
                  const respFetch = await fetch(BACKEND + "/analyze/aggregate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                  });
                  if (!respFetch.ok) {
                    safeSetText(status, "Server error: " + respFetch.status);
                    return;
                  }
                  const json = await respFetch.json();
                  renderResult(json);
                  safeSetText(status, "Analysis completed (direct backend).");
                } catch (err) {
                  console.error("direct backend analyze error:", err);
                  safeSetText(status, "Network error: is backend running?");
                }
              }
            } catch (e) {
              console.error("Reanalyze exception:", e);
              safeSetText(status, "Reanalyze failed.");
            }
          });
        });
      }

      // Details panel open/close - always attach and robustly load data
      if (detailsBtn) {
        detailsBtn.addEventListener("click", () => {
          try {
            if (detailsPanel) detailsPanel.classList.remove("hidden");
            getActiveTab((tab) => {
              if (!tab || !tab.url) return;
              try {
                if (hasChromeApi("storage") && chrome.storage && chrome.storage.local) {
                  chrome.storage.local.get(["analysis:" + tab.url], (items) => {
                    const json = items ? items["analysis:" + tab.url] : null;
                    if (json) renderResult(json);
                  });
                }
              } catch (e) {
                console.warn("Failed to load details storage:", e);
              }
            });
          } catch (e) {
            console.error("detailsBtn click err:", e);
          }
        });
      }
      if (closeDetails) {
        closeDetails.addEventListener("click", () => {
          if (detailsPanel) detailsPanel.classList.add("hidden");
        });
      }

      // Open Dashboard
      if (openDashboardBtn) {
        openDashboardBtn.addEventListener("click", () => {
          getActiveTab((tab) => {
            const dashboardBase = BACKEND + "/static/dashboard.html";
            try {
              if (tab && tab.url) {
                const urlParam = encodeURIComponent(tab.url);
                try {
                  if (hasChromeApi("tabs") && chrome.tabs.create) chrome.tabs.create({ url: dashboardBase + "?highlight=" + urlParam });
                  else window.open(dashboardBase + "?highlight=" + urlParam, "_blank");
                } catch (e) {
                  window.open(dashboardBase + "?highlight=" + urlParam, "_blank");
                }
              } else {
                try {
                  if (hasChromeApi("tabs") && chrome.tabs.create) chrome.tabs.create({ url: dashboardBase });
                  else window.open(dashboardBase, "_blank");
                } catch (e) {
                  window.open(dashboardBase, "_blank");
                }
              }
            } catch (e) {
              console.error("openDashboard error:", e);
              safeSetText(status, "Failed to open dashboard.");
            }
          });
        });
      }

      // Copy JSON
      if (copyJsonBtn) {
        copyJsonBtn.addEventListener("click", () => {
          try {
            const text = rawJson ? rawJson.textContent : "";
            if (!text) { showToast("No JSON to copy."); return; }
            navigator.clipboard.writeText(text).then(() => showToast("Raw JSON copied to clipboard.")).catch((e) => { console.error("copy failed", e); showToast("Copy failed."); });
          } catch (e) { console.error(e); showToast("Copy failure"); }
        });
      }

      // Report false positive
      if (reportFpBtn) {
        reportFpBtn.addEventListener("click", () => {
          getActiveTab((tab) => {
            if (!tab || !tab.url) { showToast("No tab to report."); return; }
            try {
              if (!hasChromeApi("storage") || !chrome.storage || !chrome.storage.local) { showToast("No analysis to report."); return; }
              chrome.storage.local.get(["analysis:" + tab.url], async (items) => {
                const json = items ? items["analysis:" + tab.url] : null;
                if (!json) { showToast("No analysis to report."); return; }
                try {
                  safeSetText(status, "Reporting false positive...");
                  const resp = await fetch(BACKEND + "/report_false_positive", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: tab.url, analysis: json, notes: "" })
                  });
                  const j = await resp.json();
                  if (j && j.ok) showToast("Reported false positive. Thank you."); else showToast("Report failed.");
                } catch (e) {
                  console.error("report_fp error", e);
                  showToast("Network error: cannot reach backend.");
                }
              });
            } catch (e) {
              console.error("reportFpBtn outer error", e);
              showToast("Report failed.");
            }
          });
        });
      }

      // Auto-analyze toggle persisted
      if (autoToggle) {
        try {
          if (hasChromeApi("storage") && chrome.storage && chrome.storage.local) {
            chrome.storage.local.get(["phishingproto_auto_analyze"], (items) => {
              try { autoToggle.checked = !!(items && items.phishingproto_auto_analyze); } catch (e) {}
            });
          }
        } catch (e) { console.warn("Failed to read auto-analyze pref:", e); }
        autoToggle.addEventListener("change", (e) => {
          try {
            if (hasChromeApi("storage") && chrome.storage && chrome.storage.local) chrome.storage.local.set({ phishingproto_auto_analyze: !!e.target.checked });
            showToast(`Auto-analyze ${e.target.checked ? 'enabled' : 'disabled'}`);
          } catch (err) { console.error("Failed to save auto-analyze pref:", err); }
        });
      }

      // keyboard shortcuts shortcuts
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && detailsPanel && !detailsPanel.classList.contains('hidden')) detailsPanel.classList.add('hidden');
        if (e.ctrlKey && e.key === 'r') { e.preventDefault(); if (reanalyzeBtn) reanalyzeBtn.click(); }
      });

      log("popup initialized");
    } catch (outerErr) {
      console.error("Popup top-level error:", outerErr);
      try { safeSetText(document.getElementById("status"), "Popup script error: see console"); } catch (e) {}
    }
  });

})();
