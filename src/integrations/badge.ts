/**
 * Security score badge generation for Ironward.
 *
 * The score uses the same weighted-penalty concept as the URL scanner
 * (`src/engines/url-scanner.ts#scoreAndGrade`) but with caps per severity
 * so a single category can't sink the entire score on its own.
 */

import type { NormalizedFinding } from "../engines/sarif.js";

export type BadgeColor = "brightgreen" | "green" | "yellow" | "orange" | "red";

const BADGE_HEX: Record<BadgeColor, string> = {
  brightgreen: "#4c1",
  green: "#97ca00",
  yellow: "#dfb317",
  orange: "#fe7d37",
  red: "#e05d44",
};

export function colorForScore(score: number): BadgeColor {
  if (score >= 90) return "brightgreen";
  if (score >= 75) return "green";
  if (score >= 60) return "yellow";
  if (score >= 40) return "orange";
  return "red";
}

/** Compute a 0-100 security score from a flat list of findings. */
export function computeSecurityScore(findings: NormalizedFinding[]): number {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "critical": critical++; break;
      case "high": high++; break;
      case "medium": medium++; break;
      case "low": low++; break;
      // info: no weight
    }
  }

  const cPenalty = Math.min(critical * 15, 75);
  const hPenalty = Math.min(high * 8, 56);
  const mPenalty = Math.min(medium * 3, 30);
  const lPenalty = Math.min(low * 1, 10);

  const raw = 100 - (cPenalty + hPenalty + mPenalty + lPenalty);
  const clamped = Math.max(0, Math.min(100, raw));
  return Math.round(clamped);
}

export interface BadgeUrlInput {
  score: number;
  label?: string;
  logo?: string;
}

export function shieldsBadgeUrl(input: BadgeUrlInput): string {
  const label = input.label ?? "security";
  const logo = input.logo ?? "shield";
  const color = colorForScore(input.score);
  // shields.io expects "label-message-color"; encodeURIComponent handles "/" as %2F.
  const message = `${input.score}/100`;
  const path = `${encodeURIComponent(label)}-${encodeURIComponent(message)}-${encodeURIComponent(color)}`;
  return `https://img.shields.io/badge/${path}?logo=${encodeURIComponent(logo)}`;
}

export type BadgeFormat = "url" | "markdown" | "html" | "json";

export function renderBadge(score: number, format: BadgeFormat, linkUrl?: string): string {
  const url = shieldsBadgeUrl({ score });
  switch (format) {
    case "url":
      return url;
    case "markdown": {
      const img = `![Ironward security: ${score}/100](${url})`;
      return linkUrl ? `[${img}](${linkUrl})` : img;
    }
    case "html": {
      const img = `<img src="${url}" alt="Ironward security: ${score}/100" />`;
      return linkUrl ? `<a href="${linkUrl}">${img}</a>` : img;
    }
    case "json":
      return JSON.stringify({
        schemaVersion: 1,
        label: "security",
        message: `${score}/100`,
        color: colorForScore(score),
      });
    default:
      return url;
  }
}

function escXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** Generate an inline SVG badge that doesn't require shields.io. */
export function renderBadgeSvg(score: number, label = "security"): string {
  const color = colorForScore(score);
  const fill = BADGE_HEX[color];
  const message = `${score}/100`;
  // approx 6px per char + 14px padding
  const labelWidth = Math.max(60, label.length * 7 + 14);
  const valueWidth = Math.max(60, message.length * 7 + 14);
  const total = labelWidth + valueWidth;
  const labelX = labelWidth / 2;
  const valueX = labelWidth + valueWidth / 2;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${escXml(label)}: ${escXml(message)}">
  <linearGradient id="g" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${fill}"/>
    <rect width="${total}" height="20" fill="url(#g)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelX}" y="14">${escXml(label)}</text>
    <text x="${valueX}" y="14">${escXml(message)}</text>
  </g>
</svg>`;
}

/** Insert or update an Ironward badge in a README. */
export function updateReadmeBadge(readmeContent: string, score: number, linkUrl: string): string {
  const url = shieldsBadgeUrl({ score });
  const badgeMd = `[![Ironward](${url})](${linkUrl})`;
  const block = `<!-- ironward-badge -->${badgeMd}<!-- /ironward-badge -->`;

  const re = /<!-- ironward-badge -->[\s\S]*?<!-- \/ironward-badge -->/;
  if (re.test(readmeContent)) {
    return readmeContent.replace(re, block);
  }

  // No existing badge: insert after first H1, or at top.
  const lines = readmeContent.split("\n");
  const headingIdx = lines.findIndex((l) => /^#\s+/.test(l));
  if (headingIdx === -1) {
    return `${block}\n\n${readmeContent}`;
  }
  const before = lines.slice(0, headingIdx + 1);
  const after = lines.slice(headingIdx + 1);
  return [...before, "", block, ...after].join("\n");
}
