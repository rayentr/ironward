import { readFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";

/**
 * Minimal .gitignore-compatible matcher.
 * Supported:
 *  - "# comment"
 *  - blank lines
 *  - "!negate"
 *  - "dir/" (trailing slash matches directories only)
 *  - "/anchor" (leading slash anchors to project root)
 *  - "*.glob", "**" segments
 */

export interface IgnoreRule {
  negate: boolean;
  dirOnly: boolean;
  anchored: boolean;
  regex: RegExp;
  raw: string;
}

export class IgnoreMatcher {
  readonly rules: IgnoreRule[];
  readonly root: string;

  constructor(root: string, patterns: string[] = []) {
    this.root = root;
    this.rules = patterns.map((p) => compilePattern(p)).filter((x): x is IgnoreRule => x !== null);
  }

  static async fromFiles(root: string, files: string[]): Promise<IgnoreMatcher> {
    const patterns: string[] = [];
    for (const f of files) {
      try {
        const content = await readFile(f, "utf8");
        for (const line of content.split(/\r?\n/)) patterns.push(line);
      } catch {
        /* file doesn't exist — that's fine */
      }
    }
    return new IgnoreMatcher(root, patterns);
  }

  /**
   * Test whether an absolute path should be ignored.
   * A path is ignored if it matches a rule OR if any of its ancestor
   * directories match a rule — gitignore-style containment.
   */
  ignores(absPath: string, isDir: boolean): boolean {
    const rel = toForwardSlash(relative(this.root, absPath));
    if (rel === "" || rel.startsWith("..")) return false;

    // Build the list of paths to check: the path itself, plus each ancestor.
    const segments = rel.split("/");
    const paths: Array<{ path: string; isDir: boolean }> = [];
    for (let i = 1; i < segments.length; i++) {
      paths.push({ path: segments.slice(0, i).join("/"), isDir: true });
    }
    paths.push({ path: rel, isDir });

    let ignored = false;
    for (const p of paths) {
      for (const rule of this.rules) {
        if (rule.dirOnly && !p.isDir) continue;
        if (rule.regex.test(p.path)) ignored = !rule.negate;
      }
    }
    return ignored;
  }
}

function toForwardSlash(p: string): string {
  return sep === "/" ? p : p.split(sep).join("/");
}

export function compilePattern(raw: string): IgnoreRule | null {
  let line = raw.replace(/\s+$/, "");
  if (!line) return null;
  if (line.startsWith("#")) return null;
  let negate = false;
  if (line.startsWith("!")) { negate = true; line = line.slice(1); }
  let dirOnly = false;
  if (line.endsWith("/")) { dirOnly = true; line = line.slice(0, -1); }
  let anchored = false;
  if (line.startsWith("/")) { anchored = true; line = line.slice(1); }
  if (!line) return null;

  // Build a regex from gitignore-style pattern.
  let rx = "";
  if (anchored) rx += "^";
  else rx += "(?:^|/)";

  let i = 0;
  while (i < line.length) {
    const c = line[i];
    const rest = line.slice(i);
    if (rest.startsWith("**/")) {
      rx += "(?:.*/)?";
      i += 3; continue;
    }
    if (rest === "**") {
      rx += ".*";
      i += 2; continue;
    }
    if (c === "*") {
      rx += "[^/]*";
      i++; continue;
    }
    if (c === "?") {
      rx += "[^/]";
      i++; continue;
    }
    if (c === "[") {
      // Character class — pass through, trust gitignore semantics.
      const end = line.indexOf("]", i);
      if (end > i) { rx += line.slice(i, end + 1); i = end + 1; continue; }
    }
    if (".+^$(){}|\\".includes(c)) rx += "\\" + c;
    else rx += c;
    i++;
  }

  rx += "(?:$|/)"; // match whole path or directory prefix
  return { negate, dirOnly, anchored, regex: new RegExp(rx), raw };
}

/** Patterns that are always ignored (build artifacts, deps, editor junk). */
export const DEFAULT_IGNORE_PATTERNS: string[] = [
  "node_modules/",
  "**/node_modules/",
  "dist/",
  "build/",
  "out/",
  "coverage/",
  ".next/",
  ".nuxt/",
  ".svelte-kit/",
  ".turbo/",
  ".parcel-cache/",
  ".cache/",
  ".venv/",
  "venv/",
  "__pycache__/",
  ".mypy_cache/",
  ".pytest_cache/",
  ".ruff_cache/",
  ".terraform/",
  ".serverless/",
  "target/",
  "vendor/",
  ".git/",
  ".hg/",
  ".svn/",
  ".idea/",
  ".vscode/",
  ".DS_Store",
  "*.min.js",
  "*.min.css",
  "*.map",
  "*.lock",
  "*.log",
  "*.tsbuildinfo",
  ".env.example",
];
