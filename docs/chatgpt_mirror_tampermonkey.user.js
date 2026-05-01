// ==UserScript==
// @name         AI Security ChatGPT Mirror
// @namespace    ai-security-monitor
// @version      1.0.0
// @description  Mirror prompts from personal ChatGPT into AI Security Monitoring Tool
// @match        https://chatgpt.com/*
// @match        https://chat.openai.com/*
// @grant        none
// ==/UserScript==

(function () {
  "use strict";

  const ENDPOINT = "http://localhost:8000/mirror/chatgpt";
  const MIRROR_KEY = "";
  let lastPrompt = "";
  let lastSentAt = 0;

  function getTextarea() {
    return document.querySelector("textarea#prompt-textarea, textarea[data-id='root']");
  }

  async function mirrorPrompt(promptText) {
    const prompt = String(promptText || "").trim();
    if (!prompt) return;
    const now = Date.now();
    if (prompt === lastPrompt && now - lastSentAt < 2000) return;
    lastPrompt = prompt;
    lastSentAt = now;

    const headers = { "Content-Type": "application/json" };
    if (MIRROR_KEY) headers["X-Mirror-Key"] = MIRROR_KEY;

    try {
      await fetch(ENDPOINT, {
        method: "POST",
        headers,
        body: JSON.stringify({
          prompt,
          source: "chatgpt_personal",
          provider: "chatgpt_personal",
          page_url: window.location.href,
        }),
      });
    } catch (err) {
      console.warn("[Mirror] failed:", err);
    }
  }

  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key !== "Enter" || e.shiftKey) return;
      const ta = getTextarea();
      if (!ta) return;
      mirrorPrompt(ta.value);
    },
    true
  );

  document.addEventListener(
    "click",
    (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      const testId = btn.getAttribute("data-testid") || "";
      const label = (btn.textContent || "").toLowerCase();
      if (testId.includes("send") || label.includes("send")) {
        const ta = getTextarea();
        if (ta) mirrorPrompt(ta.value);
      }
    },
    true
  );
})();
