import { scanUrl, formatUrlReport, type UrlScanResult, type FetchLike, type TlsProber } from "../engines/url-scanner.js";

export interface ScanUrlInput {
  url: string;
  probeExposedFiles?: boolean;
  probeErrors?: boolean;
  probeSourceMaps?: boolean;
  probeAdminPanels?: boolean;
  probeApiDocs?: boolean;
  probeEmbeddedSecrets?: boolean;
  probeTls?: boolean;
}

export async function runScanUrl(
  input: ScanUrlInput,
  fetchImpl?: FetchLike,
  tlsProber?: TlsProber,
): Promise<UrlScanResult> {
  if (!input.url) throw new Error("url is required");
  return scanUrl(input.url, fetchImpl ?? ((fetch as unknown) as FetchLike), {
    probeExposedFiles: input.probeExposedFiles,
    probeErrors: input.probeErrors,
    probeSourceMaps: input.probeSourceMaps,
    probeAdminPanels: input.probeAdminPanels,
    probeApiDocs: input.probeApiDocs,
    probeEmbeddedSecrets: input.probeEmbeddedSecrets,
    probeTls: input.probeTls,
    tlsProber,
  });
}

export { formatUrlReport };
