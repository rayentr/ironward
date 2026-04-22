// Properly sanitized / safely rendered — pre-filter should NOT flag.

import DOMPurify from "dompurify";

function renderMessage(raw) {
  // Safe: DOMPurify strips XSS before injecting HTML.
  const clean = DOMPurify.sanitize(raw);
  document.getElementById("msg").innerHTML = clean;
}

function renderName(raw) {
  // Safe: textContent never interprets HTML.
  document.getElementById("name").textContent = raw;
}

// Safe static string — no user input.
element.innerHTML = "<strong>Loading…</strong>";
