// background.js - PhishingProto background/service worker

const BACKEND_BASE = "http://127.0.0.1:5000";
const BACKEND_ANALYZE = BACKEND_BASE + "/analyze/aggregate";

// Debug/resilient fetch helper with retry
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

// helper to set a small badge indicating suspicion (optional)
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

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyze_page") {
    (async () => {
      try {
        const payload = Object.assign({}, message.payload, { client_extension_version: "0.9.0" });
        const result = await fetchWithTimeoutDebug(BACKEND_ANALYZE, payload, 15000, true);
        if (!result || !result.ok) {
          const errMsg = `Backend error: ${result ? result.status : "network"}`;
          console.error("analyze_page error:", errMsg);
          sendResponse({ ok: false, error: errMsg });
          return;
        }
        const backendResp = result.json || {};
        if (!backendResp.timestamp) backendResp.timestamp = new Date().toISOString();
        const storageKey = `analysis:${message.payload.url}`;
        const toStore = {};
        toStore[storageKey] = backendResp;
        if (sender && sender.tab && sender.tab.id) toStore[`tab:${sender.tab.id}`] = message.payload.url;
        chrome.storage.local.set(toStore, () => {
          // set badge
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

  // other messages - allow default
});
