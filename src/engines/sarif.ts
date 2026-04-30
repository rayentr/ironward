/**
 * SARIF 2.1.0 converters for Ironward findings.
 *
 * Minimal, schema-valid output that GitHub's `codeql-action/upload-sarif`
 * accepts. We intentionally do NOT include optional fields that add weight
 * without adding value in the GitHub Security tab.
 */

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  help?: { text: string; markdown?: string };
  helpUri?: string;
  defaultConfiguration?: { level: SarifLevel };
  properties?: { tags?: string[]; "security-severity"?: string };
}

export type SarifLevel = "error" | "warning" | "note" | "none";

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; startColumn?: number; endLine?: number; endColumn?: number };
    };
  }>;
  partialFingerprints?: Record<string, string>;
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

export interface SarifLog {
  version: "2.1.0";
  $schema: string;
  runs: SarifRun[];
}

export function sarifLevelForSeverity(sev: string): SarifLevel {
  switch (sev) {
    case "critical":
    case "high": return "error";
    case "medium": return "warning";
    case "low":
    case "info": return "note";
    default: return "warning";
  }
}

export interface NormalizedExploit {
  title: string;
  poc: string;
  impact: string;
  cvss: number;
  cvssVector: string;
  owasp: string;
  cwe: string;
  remediation: string;
  references: string[];
}

/** Normalized finding that every Ironward scanner can produce before SARIF emission. */
export interface NormalizedFinding {
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  file: string;
  line: number;
  column?: number;
  tool: string;                     // scan_for_secrets / scan_code / scan_deps / …
  fingerprint?: string;
  exploit?: NormalizedExploit;
}

export function buildSarif(
  findings: NormalizedFinding[],
  version: string,
  informationUri = "https://github.com/rayentr/ironward",
): SarifLog {
  // Dedupe rules by (tool, ruleId) — SARIF requires one rule object per ruleId per run.
  const rulesByKey = new Map<string, SarifRule>();
  const seenRuleIds = new Set<string>();
  for (const f of findings) {
    const ruleKey = `${f.tool}::${f.ruleId}`;
    if (rulesByKey.has(ruleKey)) continue;
    const ex = f.exploit;
    const helpText = ex
      ? `${ex.title}\n\n${ex.poc}\n\nImpact: ${ex.impact}\n\nCVSS: ${ex.cvss.toFixed(1)} (${ex.cvssVector})\nOWASP: ${ex.owasp}\nCWE: ${ex.cwe}\n\nFix: ${ex.remediation}${ex.references.length ? "\n\nReferences:\n" + ex.references.map((r) => `- ${r}`).join("\n") : ""}`
      : undefined;
    const helpMd = ex
      ? `### ${ex.title}\n\n**Proof of concept**\n\n\`\`\`\n${ex.poc}\n\`\`\`\n\n**Impact:** ${ex.impact}\n\n| | |\n|---|---|\n| CVSS | ${ex.cvss.toFixed(1)} (${ex.cvssVector}) |\n| OWASP | ${ex.owasp} |\n| CWE | ${ex.cwe} |\n\n**Fix:** ${ex.remediation}${ex.references.length ? "\n\n**References**\n" + ex.references.map((r) => `- <${r}>`).join("\n") : ""}`
      : undefined;
    const props: NonNullable<SarifRule["properties"]> = { tags: [f.tool, `severity:${f.severity}`] };
    if (ex) props["security-severity"] = ex.cvss.toFixed(1);
    rulesByKey.set(ruleKey, {
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: f.title.slice(0, 120) },
      fullDescription: { text: f.description.slice(0, 500) || f.title },
      defaultConfiguration: { level: sarifLevelForSeverity(f.severity) },
      properties: props,
      ...(helpText ? { help: { text: helpText, ...(helpMd ? { markdown: helpMd } : {}) } } : {}),
    });
    seenRuleIds.add(f.ruleId);
  }

  const results: SarifResult[] = findings.map((f) => ({
    ruleId: f.ruleId,
    level: sarifLevelForSeverity(f.severity),
    message: { text: f.description || f.title },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.file.replace(/^\.\//, "") },
        region: {
          startLine: Math.max(1, f.line),
          ...(f.column ? { startColumn: f.column } : {}),
        },
      },
    }],
    ...(f.fingerprint ? { partialFingerprints: { ironwardFingerprint: f.fingerprint } } : {}),
  }));

  return {
    version: "2.1.0",
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "Ironward",
          version,
          informationUri,
          rules: [...rulesByKey.values()],
        },
      },
      results,
    }],
  };
}
