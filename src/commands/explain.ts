import { CODE_RULES, type CodeRule } from "../engines/code-rules.js";
import { generateExploit } from "../engines/exploit-generator.js";

function pickFlag(rest: string[], flag: string): string | undefined {
  const eq = rest.find((a) => a.startsWith(`${flag}=`));
  if (eq) return eq.slice(flag.length + 1);
  const i = rest.indexOf(flag);
  if (i >= 0 && i + 1 < rest.length) return rest[i + 1];
  return undefined;
}
function hasFlag(rest: string[], flag: string): boolean {
  return rest.includes(flag);
}

function languagesFor(rule: CodeRule): string {
  return rule.languages?.join(", ") ?? "(any)";
}

function severityBadge(s: string): string {
  return s.toUpperCase();
}

function listAll(): number {
  // Group by category for readability.
  const byCat = new Map<string, CodeRule[]>();
  for (const r of CODE_RULES) {
    const list = byCat.get(r.category) ?? [];
    list.push(r);
    byCat.set(r.category, list);
  }
  const cats = [...byCat.keys()].sort();
  console.log(`Ironward — ${CODE_RULES.length} rules across ${cats.length} categories\n`);
  for (const cat of cats) {
    const rules = byCat.get(cat)!.sort((a, b) => a.id.localeCompare(b.id));
    console.log(`── ${cat} (${rules.length}) ──`);
    for (const r of rules) {
      console.log(`  ${r.id.padEnd(48)} [${severityBadge(r.severity)}] ${r.title}`);
    }
    console.log("");
  }
  console.log(`Run: ironward explain <rule-id>   for full detail.`);
  return 0;
}

function listCategory(category: string): number {
  const rules = CODE_RULES.filter((r) => r.category === category).sort((a, b) => a.id.localeCompare(b.id));
  if (rules.length === 0) {
    const cats = [...new Set(CODE_RULES.map((r) => r.category))].sort();
    console.error(`No rules in category "${category}".`);
    console.error(`Available categories: ${cats.join(", ")}`);
    return 2;
  }
  console.log(`── ${category} (${rules.length} rules) ──\n`);
  for (const r of rules) {
    console.log(`${r.id}   [${severityBadge(r.severity)}]   ${r.title}`);
    console.log(`  ${r.rationale}`);
    console.log("");
  }
  return 0;
}

function explainOne(ruleId: string): number {
  const rule = CODE_RULES.find((r) => r.id === ruleId);
  if (!rule) {
    // Suggest near-matches by simple substring.
    const suggestions = CODE_RULES
      .filter((r) => r.id.includes(ruleId) || ruleId.includes(r.id))
      .slice(0, 8)
      .map((r) => r.id);
    console.error(`Unknown rule id: ${ruleId}`);
    if (suggestions.length > 0) {
      console.error(`Did you mean:`);
      for (const s of suggestions) console.error(`  ${s}`);
    } else {
      console.error(`Run \`ironward explain --list\` to see all rule ids.`);
    }
    return 2;
  }

  // Generate a representative PoC by feeding a synthetic finding through the exploit engine.
  const exploit = generateExploit(rule.id, {
    ruleId: rule.id,
    severity: rule.severity,
    category: rule.category,
    title: rule.title,
    line: 1,
    column: 1,
    snippet: "",
    rationale: rule.rationale,
    fix: rule.fix,
  }, "", "javascript", "");

  const lines: string[] = [];
  lines.push(`${rule.id} — ${rule.title}`);
  lines.push("━".repeat(Math.min(72, Math.max(20, (rule.id.length + rule.title.length + 3)))));
  lines.push(`Category:   ${rule.category}`);
  lines.push(`Severity:   ${severityBadge(rule.severity)}`);
  if (rule.confidence != null) lines.push(`Confidence: ${rule.confidence}`);
  if (rule.owasp) lines.push(`OWASP:      ${rule.owasp}`);
  if (exploit.cwe) lines.push(`CWE:        ${exploit.cwe}`);
  lines.push(`Languages:  ${languagesFor(rule)}`);
  lines.push("");
  lines.push("WHAT IT DETECTS");
  lines.push(`  ${rule.rationale}`);
  lines.push("");
  lines.push("PATTERN");
  lines.push(`  ${rule.re.source}`);
  if (rule.negativePattern) {
    lines.push("");
    lines.push("SAFE-PATTERN GUARD (suppresses match when present in scope)");
    lines.push(`  ${rule.negativePattern.source}`);
  }
  lines.push("");
  lines.push("FIX");
  lines.push(`  ${rule.fix}`);
  lines.push("");
  lines.push("PROOF OF CONCEPT");
  for (const l of exploit.poc.split("\n")) lines.push(`  ${l}`);
  lines.push("");
  lines.push(`IMPACT: ${exploit.impact}`);
  lines.push(`CVSS:   ${exploit.cvss.toFixed(1)} (${exploit.cvssVector})`);
  if (exploit.references?.length) {
    lines.push("");
    lines.push("REFERENCES");
    for (const r of exploit.references) lines.push(`  ${r}`);
  }
  console.log(lines.join("\n"));
  return 0;
}

export async function runExplain(rest: string[]): Promise<number> {
  if (hasFlag(rest, "--list")) return listAll();
  const cat = pickFlag(rest, "--category");
  if (cat) return listCategory(cat);
  const positional = rest.find((a) => !a.startsWith("--"));
  if (!positional) {
    console.error("Usage: ironward explain <rule-id>");
    console.error("       ironward explain --list");
    console.error("       ironward explain --category <name>");
    return 2;
  }
  return explainOne(positional);
}
