// background.js - PhishingProto background/service worker
// Updated: preserves original behavior but adds explicit run_models handling
// so content script can request targeted runs (cnn / gnn) and get predictable payloads.

// -----------------------------
// CONFIG
// -----------------------------
const BACKEND_BASE = "http://127.0.0.1:5000";
const BACKEND_ANALYZE = BACKEND_BASE + "/analyze/aggregate";
const BACKEND_ANALYZE_MULTI = BACKEND_BASE + "/analyze/multi";

// Debug/resilient fetch helper with retry (original; unchanged)
async function fetchWithTimeoutDebug(url, bodyJson, timeout = 15000, retry = true) {
  const doFetch = async () => {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      console.debug("background:fetch ->", url, "payload:", bodyJson);
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bodyJson),
        signal: controller.signal,
      });
      clearTimeout(id);
      const text = await res.text().catch(() => "");
      let json = null;
      try { json = JSON.parse(text); } catch (e) {}
      return { ok: res.ok, status: res.status, json, text };
    } catch (err) {
      clearTimeout(id);
      console.error("background:fetch network/error ->", err);
      throw err;
    }
  };

  try {
    return await doFetch();
  } catch (err) {
    if (retry) {
      console.warn("background:fetch failed, retrying once:", err);
      await new Promise(r => setTimeout(r, 500));
      try { return await doFetch(); } catch (err2) { console.error("background:fetch retry failed", err2); throw err2; }
    }
    throw err;
  }
}

// helper to set a small badge indicating suspicion (optional) - unchanged
function setBadge(scoreOrLabel) {
  try {
    let text = "";
    let color = "#0f8a2f";
    if (typeof scoreOrLabel === "number") {
      const s = scoreOrLabel;
      if (s >= 0.6) { text = "!"; color = "#c0392b"; }
      else if (s >= 0.35) { text = "!"; color = "#e67e22"; }
    } else if (typeof scoreOrLabel === "string") {
      const l = scoreOrLabel.toLowerCase();
      if (l === "high") { text = "!"; color = "#c0392b"; }
      else if (l === "medium") { text = "!"; color = "#e67e22"; }
    }
    chrome.action.setBadgeText({ text: text });
    chrome.action.setBadgeBackgroundColor({ color });
  } catch (e) {
    // ignore if not supported
  }
}

// -----------------------------
// Helpers for routing decisions
// -----------------------------
function payloadRequestsModels(rawPayload) {
  if (!rawPayload) return null;
  if (Array.isArray(rawPayload.run_models) && rawPayload.run_models.length > 0) {
    return rawPayload.run_models.map(x => String(x).toLowerCase());
  }
  const t = (rawPayload.type || rawPayload.trigger || "").toString().toLowerCase();
  const found = [];
  if (t.includes("cnn")) found.push("cnn");
  if (t.includes("gnn") || t.includes("graph")) found.push("gnn");
  return found.length ? found : null;
}

// Build a consistent analyze payload for /analyze/multi
function buildMultiPayload(raw) {
  const payload = {
    url: raw.url || raw.pageUrl || "",
    domain: raw.domain || raw.hostname || "",
    title: raw.title || "",
    text: raw.text || "",
    meta_description: raw.meta_description || "",
    trigger: raw.trigger || raw.type || "manual",
    timestamp: raw.timestamp || new Date().toISOString(),
  };
  // forward image if present (content_script sets image_b64 when doing CNN)
  if (raw.image_b64) payload.image_b64 = raw.image_b64;
  // explicit run_models if provided
  if (Array.isArray(raw.run_models) && raw.run_models.length) {
    payload.run_models = raw.run_models.map(x => String(x).toLowerCase());
  } else {
    const inferred = payloadRequestsModels(raw);
    if (inferred) payload.run_models = inferred;
  }
  // pass some optional metadata
  ["source","note","user","session_id","context"].forEach(k => { if (k in raw) payload[k] = raw[k]; });
  return payload;
}

// Existing legacy aggregate payload passthrough (we forward raw payload as-is)
function buildAggregatePayload(raw) {
  // keep original behavior: we post whatever content_script sent (plus client version)
  return Object.assign({}, raw);
}

// -----------------------------
// Message handler
// -----------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyze_page") {
    (async () => {
      try {
        // maintain original client_extension_version tag
        const incoming = Object.assign({}, message.payload || {}, { client_extension_version: "0.9.0" });

        // Decide whether the caller requested specific model runs (cnn/gnn) or not
        // ALWAYS use /analyze/multi for page analysis so backend runs all models and we get consistent CSV rows
let fetchTarget = BACKEND_ANALYZE_MULTI;
let bodyToSend = buildMultiPayload(incoming);
// Force explicit run of all three components
bodyToSend.run_models = ["text", "cnn", "gnn"];
console.debug("[background] analyze_page -> forcing /analyze/multi run_models:", bodyToSend.run_models, "url:", bodyToSend.url);


        const result = await fetchWithTimeoutDebug(fetchTarget, bodyToSend, 15000, true);
        if (!result || !result.ok) {
          const errMsg = `Backend error: ${result ? result.status : "network"}`;
          console.error("analyze_page error:", errMsg);
          sendResponse({ ok: false, error: errMsg });
          return;
        }

        // prefer parsed JSON (result.json) if present, else attempt to parse text
        const backendResp = result.json || {};
        if (!backendResp.timestamp) backendResp.timestamp = new Date().toISOString();

        // store under analysis:<url>
        const storageKey = `analysis:${incoming.url || bodyToSend.url || ""}`;
        const toStore = {};
        toStore[storageKey] = backendResp;
        if (sender && sender.tab && sender.tab.id) toStore[`tab:${sender.tab.id}`] = incoming.url || bodyToSend.url || "";

        chrome.storage.local.set(toStore, () => {
          // set badge (keep original logic)
          try {
            const agg = backendResp.aggregate_score ?? (backendResp.text && backendResp.text.score) ?? 0;
            setBadge(agg);
          } catch (e) {}
          sendResponse({ ok: true, result: backendResp });
        });
      } catch (err) {
        console.error("background: analyze_page error", err);
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true; // async response
  }

  if (message.action === "report_false_positive") {
    (async () => {
      try {
        const payload = message.payload || {};
        const result = await fetchWithTimeoutDebug(BACKEND_BASE + "/report/false_positive", payload, 10000, true);
        if (result && result.ok) {
          sendResponse({ ok: true, message: "Site reported as safe" });
        } else {
          sendResponse({ ok: false, error: "Failed to report false positive" });
        }
      } catch (err) {
        console.error("background: report_false_positive error", err);
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }

  if (message.action === "open_popup_for_url") {
    const url = message.url;
    chrome.storage.local.set({ phishingproto_last_requested_url: url }, () => {
      try {
        if (chrome.action && chrome.action.openPopup) {
          chrome.action.openPopup();
          sendResponse({ ok: true });
        } else {
          chrome.tabs.create({ url: chrome.runtime.getURL("popup.html") }, () => sendResponse({ ok: true }));
        }
      } catch (e) {
        console.error("open_popup_for_url error", e);
        sendResponse({ ok: false, error: String(e) });
      }
    });
    return true;
  }

  // other messages - allow default (no change)
});
