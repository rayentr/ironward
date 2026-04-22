/**
 * Confidence scoring for secret findings.
 *
 * Each finding starts at a baseline derived from its source (pattern vs entropy).
 * Signals from the surrounding context nudge the score up or down.
 *
 * Final scale:
 *   90-100  definite — exact format match + strong context (e.g. AKIA… next to "aws_key =")
 *   75-89   high     — pattern match or strong entropy + supportive context
 *   60-74   medium   — pattern match but ambiguous context
 *   40-59   low      — probably a false positive; hidden unless --verbose
 *   < 40    suppress — likely fixture / docs / placeholder
 */

export interface ConfidenceContext {
  /** The matched string (redacted or raw). */
  match: string;
  /** The full line on which the match starts (for context sniffing). */
  line: string;
  /** The previous line (for inline comment allowlists). */
  prevLine?: string;
  /** Absolute or project-relative path. */
  path: string;
  /** Source of the finding. */
  source: "pattern" | "entropy";
  /** Pre-computed Shannon entropy (optional; used for entropy-sourced findings). */
  entropy?: number;
  /** Raw severity from the pattern definition. */
  severity?: "critical" | "high" | "medium" | "low";
}

export interface ConfidenceResult {
  score: number;               // 0-100
  reasons: string[];           // human-readable contributing signals
}

// Treat underscore as a word separator (AWS_SECRET_KEY should match "secret").
const SECRET_NAME_HINTS = /(?:^|[^a-zA-Z])(?:key|secret|token|password|passwd|pwd|credential|apikey|auth|bearer|session|jwt|webhook)(?:$|[^a-zA-Z])/i;
const NEGATIVE_NAME_HINTS = /(?:^|[^a-zA-Z])(?:test|mock|fake|sample|example|fixture|demo|dummy|dev|placeholder)(?:$|[^a-zA-Z])/i;
const COMMENT_MARKER_HINTS = /(?:^|[^a-zA-Z])(?:example|placeholder|sample|fixture|demo|todo|template|not[ _-]?a[ _-]?real)(?:$|[^a-zA-Z])/i;

export function scoreConfidence(ctx: ConfidenceContext): ConfidenceResult {
  const reasons: string[] = [];
  let score: number;

  // Baseline: pattern matches are strong signal; entropy alone is weak.
  if (ctx.source === "pattern") {
    score = 75;
    reasons.push("pattern match (+75)");
  } else {
    score = 50;
    reasons.push("entropy heuristic (+50)");
  }

  // — Positive: secret-named variable on the line ("API_KEY = ...").
  if (SECRET_NAME_HINTS.test(ctx.line)) {
    score += 10;
    reasons.push("secret-named variable (+10)");
  }

  // — Positive: direct string-literal assignment pattern on the line.
  if (/=\s*['"`]/.test(ctx.line)) {
    score += 5;
    reasons.push("literal assignment (+5)");
  }

  // — Positive: high entropy, if measured.
  if (ctx.entropy && ctx.entropy >= 5.0) {
    score += 5;
    reasons.push(`H≥5.0 (+5)`);
  }

  // — Positive: path looks like a real env / config file.
  const lowerPath = ctx.path.toLowerCase();
  if (/\.env(?:\.|$)/.test(lowerPath) || /\/config\b/.test(lowerPath) || /secrets?\.(?:json|yaml|yml|toml)$/.test(lowerPath)) {
    score += 10;
    reasons.push("sensitive file path (+10)");
  }

  // — Negative: path smells like a test/fixture/example.
  if (/\/(?:tests?|__tests__|spec|fixtures?|examples?|mocks?|samples?|demos?|benchmarks?)\//.test(lowerPath)) {
    score -= 30;
    reasons.push("fixture/test path (-30)");
  }

  // — Negative: documentation file.
  if (/\.(?:md|mdx|rst|adoc|txt)$/.test(lowerPath)) {
    score -= 15;
    reasons.push("documentation file (-15)");
  }

  // — Negative: comment marker on same or previous line ("example", "TODO", etc.).
  if (COMMENT_MARKER_HINTS.test(ctx.line) || (ctx.prevLine && COMMENT_MARKER_HINTS.test(ctx.prevLine))) {
    // Require a comment syntax in the same line/prev so we don't over-match identifiers named "example".
    const hasComment = /(?:\/\/|\/\*|#|<!--|--)/.test(ctx.line) || (ctx.prevLine && /(?:\/\/|\/\*|#|<!--|--)/.test(ctx.prevLine));
    if (hasComment) {
      score -= 30;
      reasons.push("placeholder/example comment (-30)");
    } else {
      score -= 10;
      reasons.push("placeholder hint in identifier (-10)");
    }
  }

  // — Negative: variable name explicitly looks test-ish.
  if (NEGATIVE_NAME_HINTS.test(ctx.line) && !SECRET_NAME_HINTS.test(ctx.line)) {
    score -= 15;
    reasons.push("test/mock context (-15)");
  }

  // — Negative: match is very short (below typical token length).
  if (ctx.match.length < 16) {
    score -= 10;
    reasons.push("short match (-10)");
  }

  // Clamp.
  if (score < 0) score = 0;
  if (score > 100) score = 100;

  return { score, reasons };
}

export type ConfidenceTier = "definite" | "high" | "medium" | "low" | "suppressed";

export function confidenceTier(score: number): ConfidenceTier {
  if (score >= 90) return "definite";
  if (score >= 75) return "high";
  if (score >= 60) return "medium";
  if (score >= 40) return "low";
  return "suppressed";
}
