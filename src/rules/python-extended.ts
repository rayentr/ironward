import type { CodeRule } from "../engines/code-rules.js";

export const PYTHON_EXTENDED_RULES: CodeRule[] = [
  {
    id: "py-flask-secret-key-too-short",
    severity: "high",
    category: "python" as any,
    owasp: "A02:2021 Cryptographic Failures",
    languages: ["python"],
    title: "Flask SECRET_KEY assigned a short literal (<16 chars)",
    re: /app\s*\.\s*config\s*\[\s*['"]SECRET_KEY['"]\s*\]\s*=\s*['"][^'"]{1,15}['"]/g,
    rationale:
      "Flask uses SECRET_KEY for session cookies and CSRF tokens. A short or guessable value can be brute-forced and used to forge sessions.",
    fix: "Generate 32+ bytes with secrets.token_urlsafe(64) and read from env: app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY'].",
  },
  // py-django-allowed-hosts-wildcard moved to python.ts (deduped during 3.0.0 wiring)
  {
    id: "py-django-csrf-exempt",
    severity: "high",
    category: "python" as any,
    owasp: "A01:2021 Broken Access Control",
    languages: ["python"],
    title: "@csrf_exempt decorator on a Django view",  // ironward-ignore
    re: /@csrf_exempt\b/g,  // ironward-ignore
    rationale:
      "csrf_exempt removes Django's CSRF middleware for the view — any authenticated user can be tricked into POSTing from a malicious site.",
    fix: "Keep CSRF on. For JSON APIs, use SessionAuthentication with CSRF or move to TokenAuthentication and require Authorization headers.",
  },
  {
    id: "py-django-debug-toolbar-import",
    severity: "medium",
    category: "python" as any,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["python"],
    title: "django-debug-toolbar imported without an environment guard",
    re: /^\s*import\s+debug_toolbar\b/gm,
    rationale:
      "debug_toolbar exposes SQL, settings, and request internals. Importing unconditionally risks shipping it to production where it leaks data.",
    fix: "Wrap the import behind a DEBUG / environment check: if DEBUG: import debug_toolbar; or use django-environ to gate at INSTALLED_APPS level.",
  },
  {
    id: "py-sqlalchemy-text-injection",
    severity: "critical",
    category: "python" as any,
    owasp: "A03:2021 Injection",
    languages: ["python"],
    title: "sqlalchemy.text() built with f-string or string concat from user input",
    re: /\btext\s*\(\s*(?:f['"][^'"]*\{[^}]+\}[^'"]*['"]|['"][^'"]+['"]\s*\+\s*\w+)/g,
    rationale:
      "text() with interpolation defeats SQLAlchemy's parameter binding — any user value becomes raw SQL and is direct injection.",
    fix: "Pass parameters via .params() or use bound markers: text('SELECT * FROM t WHERE id = :id').bindparams(id=user_id).",
  },
  {
    id: "py-celery-pickle-serializer",
    severity: "critical",
    category: "python" as any,
    owasp: "A08:2021 Software and Data Integrity Failures",
    languages: ["python"],
    title: "Celery configured with pickle serializer / accept_content",
    re: /\b(?:task_serializer\s*=\s*['"]pickle['"]|accept_content\s*=\s*\[[^\]]*['"]pickle['"][^\]]*\])/g,
    rationale:
      "Pickle on the task broker = RCE on every worker the second a malicious message is queued. Trivially exploited if the broker has any open ingress.",
    fix: "Use 'json' serializer (the Celery default in 4.x+) and remove 'pickle' from accept_content.",
  },
  {
    id: "py-requests-no-timeout",
    severity: "medium",
    category: "python" as any,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["python"],
    title: "requests.get/post called without timeout=",
    re: /\brequests\s*\.\s*(?:get|post|put|delete|patch|head)\s*\(\s*[^)]*\)/g,
    negativePattern: /timeout\s*=/,
    rationale:
      "Without timeout, a slow upstream can hang the worker forever — one stuck request ties up a thread/process and snowballs to outage.",
    fix: "Always pass timeout=(connect, read), e.g. requests.get(url, timeout=(3.05, 27)).",
  },
  {
    id: "py-xml-minidom-external-entities",
    severity: "high",
    category: "python" as any,
    owasp: "A03:2021 Injection",
    languages: ["python"],
    title: "xml.dom.minidom.parseString without disabling external entities",
    re: /\bxml\.dom\.minidom\s*\.\s*parseString\s*\(/g,
    rationale:
      "minidom resolves DTDs and external entities by default — XXE lets attackers read arbitrary local files or SSRF internal hosts.",
    fix: "Use defusedxml.minidom.parseString instead, or set forbid_dtd=True if available.",
  },
  // py-tempfile-mktemp moved to python.ts (deduped during 3.0.0 wiring)
  {
    id: "py-glob-user-input",
    severity: "high",
    category: "python" as any,
    owasp: "A01:2021 Broken Access Control",
    languages: ["python"],
    title: "glob.glob() called with request input (path traversal)",
    re: /\bglob\s*\.\s*glob\s*\(\s*(?:request\s*\.|flask\s*\.\s*request\s*\.)/g,
    rationale:
      "User-controlled glob patterns can read arbitrary files — '../*/*.env' walks out of the intended directory and lists secrets.",
    fix: "Resolve the pattern against a known base, then assert each resolved match starts with that base before opening.",
  },
];
