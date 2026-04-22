export interface XssSuspect {
  line: number;
  snippet: string;
  reason: string;
}

const ID = "[A-Za-z_$][A-Za-z0-9_$.\\[\\]]*";

const RULES: Array<{ name: string; re: RegExp; reason: string }> = [
  {
    name: "dom_innerhtml_assignment",
    re: new RegExp(`\\.innerHTML\\s*=\\s*${ID}`, "g"),
    reason: "Element.innerHTML assigned from a non-literal (DOM XSS sink)",
  },
  {
    name: "dom_outerhtml_assignment",
    re: new RegExp(`\\.outerHTML\\s*=\\s*${ID}`, "g"),
    reason: "Element.outerHTML assigned from a non-literal (DOM XSS sink)",
  },
  {
    name: "document_write",
    re: /\bdocument\s*\.\s*write(?:ln)?\s*\(/g,
    reason: "document.write / writeln call",
  },
  {
    name: "insert_adjacent_html",
    re: new RegExp(`\\.insertAdjacentHTML\\s*\\(\\s*["'][^"']+["']\\s*,\\s*${ID}`, "g"),
    reason: "insertAdjacentHTML with a non-literal payload",
  },
  {
    name: "jquery_html_method",
    re: new RegExp(`\\$\\([^)]*\\)\\.html\\s*\\(\\s*${ID}`, "g"),
    reason: "jQuery .html() called with a non-literal",
  },
  {
    name: "jquery_append_with_html",
    re: /\$\([^)]*\)\.append\s*\(\s*[`"']<[^`"']*\$\{/g,
    reason: "jQuery .append() with interpolated HTML template",
  },
  {
    name: "react_dangerouslysetinnerhtml",
    re: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
    reason: "React dangerouslySetInnerHTML",
  },
  {
    name: "vue_v_html",
    re: /\bv-html\s*=\s*["']/g,
    reason: "Vue v-html directive",
  },
  {
    name: "angular_bypass_security",
    re: /\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(/g,
    reason: "Angular bypassSecurityTrust* — safety bypassed",
  },
  {
    name: "angular_inner_html_binding",
    re: /\[innerHTML\]\s*=\s*["']/g,
    reason: "Angular [innerHTML] property binding",
  },
  {
    name: "svelte_html_block",
    re: /\{@html\s+/g,
    reason: "Svelte {@html} block",
  },
  {
    name: "solid_innerhtml_prop",
    re: /\binnerHTML\s*=\s*\{[^}]+\}/g,
    reason: "SolidJS innerHTML={} prop",
  },
  {
    name: "eval_call",
    re: /\beval\s*\(/g, // ironward-ignore
    reason: "eval() call — executes arbitrary code", // ironward-ignore
  },
  {
    name: "new_function",
    re: /\bnew\s+Function\s*\(/g, // ironward-ignore
    reason: "new Function() constructor — eval equivalent", // ironward-ignore
  },
  {
    name: "settimeout_string",
    re: /\bset(?:Timeout|Interval)\s*\(\s*[`"'][^`"']*\$\{/g,
    reason: "setTimeout/setInterval with a string-interpolated callback",
  },
  {
    name: "res_send_template",
    re: /\bres\.(?:send|write|end)\s*\(\s*`[^`]*\$\{[^}]*(?:req\.|request\.|ctx\.)/g,
    reason: "Express/Koa response built from a template literal with request input",
  },
  {
    name: "res_send_concat",
    re: /\bres\.(?:send|write|end)\s*\(\s*["'`][^"'`]*["'`]\s*\+\s*(?:req|request|ctx)\./g,
    reason: "Response concatenated with request input (reflected XSS)",
  },
  {
    name: "template_render_unescaped_ejs",
    re: /<%-\s*[^%]+%>/g,
    reason: "EJS <%- %> unescaped output",
  },
  {
    name: "template_render_unescaped_mustache",
    re: /\{\{\{[^}]+\}\}\}/g,
    reason: "Handlebars/Mustache {{{ }}} triple-brace unescaped output",
  },
  {
    name: "django_safe_filter",
    re: /\|\s*safe\s*[}%]/g,
    reason: "Django |safe filter disables escaping",
  },
  {
    name: "flask_markup",
    re: /\bMarkup\s*\(\s*(?:request|f["'])/g,
    reason: "Flask Markup() wrapping request data or f-string",
  },
  {
    name: "jinja_autoescape_off",
    re: /autoescape\s*=\s*False/g,
    reason: "Jinja2 autoescape disabled",
  },
  {
    name: "php_echo_get_post",
    re: /\becho\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/g,
    reason: "PHP echo of unsanitized superglobal input",
  },
  {
    name: "php_print_get_post",
    re: /\bprint\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/g,
    reason: "PHP print of unsanitized superglobal input",
  },
  {
    name: "location_href_assignment",
    re: /\b(?:window\.)?location(?:\.href)?\s*=\s*[A-Za-z_$]/g,
    reason: "location / location.href assignment (potential open redirect / javascript: URI)",
  },
];

function lineFromIndex(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function truncate(s: string, n = 160): string {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

const SANITIZER_LINES = [
  /\bDOMPurify\.sanitize\s*\(/,
  /\bsanitize-html\b/,
  /\btextContent\s*=/,
  /\binnerText\s*=/,
  /\bescapeHtml\s*\(/,
  /\bhtml-escape\b/,
  /\bhe\.encode\s*\(/,
];

function lineContent(text: string, line: number): string {
  const lines = text.split("\n");
  return lines[line - 1] ?? "";
}

function looksSanitized(text: string, line: number): boolean {
  const current = lineContent(text, line);
  const prev = lineContent(text, line - 1);
  const source = `${prev}\n${current}`;
  return SANITIZER_LINES.some((re) => re.test(source));
}

export function findXssSuspects(code: string): XssSuspect[] {
  const suspects: XssSuspect[] = [];
  const seen = new Set<string>();
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.re.exec(code)) !== null) {
      const line = lineFromIndex(code, m.index);
      const key = `${line}:${rule.reason}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (looksSanitized(code, line)) continue;
      suspects.push({
        line,
        snippet: truncate(m[0].replace(/\s+/g, " ").trim()),
        reason: rule.reason,
      });
    }
  }
  suspects.sort((a, b) => a.line - b.line);
  return suspects;
}
