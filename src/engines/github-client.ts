export interface GitHubFile {
  path: string;
  content: string;
  sha?: string;
}

export interface CreatePullRequestOpts {
  title: string;
  body: string;
  head: string;
  base: string;
}

export interface CreatedPullRequest {
  url: string;
  number: number;
}

export interface GitHubClient {
  getDefaultBranch(owner: string, repo: string): Promise<string>;
  getFile(owner: string, repo: string, path: string, ref?: string): Promise<GitHubFile>;
  createBranch(owner: string, repo: string, branch: string, fromRef: string): Promise<void>;
  upsertFile(
    owner: string,
    repo: string,
    branch: string,
    path: string,
    content: string,
    message: string,
    sha?: string,
  ): Promise<void>;
  createPullRequest(owner: string, repo: string, opts: CreatePullRequestOpts): Promise<CreatedPullRequest>;
}

export class MissingGitHubTokenError extends Error {
  constructor() {
    super(
      "GITHUB_TOKEN is not set. Add it to your MCP client's env block to use fix_and_pr. " +
        "The token needs `repo` scope (or `contents: write` + `pull_requests: write` on fine-grained).",
    );
    this.name = "MissingGitHubTokenError";
  }
}

type Fetcher = typeof fetch;

export interface GitHubRestOpts {
  token?: string;
  baseUrl?: string;
  fetchImpl?: Fetcher;
}

export class GitHubRestClient implements GitHubClient {
  private token: string;
  private baseUrl: string;
  private fetchImpl: Fetcher;

  constructor(opts: GitHubRestOpts = {}) {
    const token = opts.token ?? process.env.GITHUB_TOKEN ?? "";
    if (!token) throw new MissingGitHubTokenError();
    this.token = token;
    this.baseUrl = opts.baseUrl ?? "https://api.github.com";
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private async call<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${this.token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ironward",
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...(init.headers as Record<string, string> | undefined),
      },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`GitHub ${init.method ?? "GET"} ${path} failed: ${res.status} ${text.slice(0, 200)}`);
    }
    return (await res.json()) as T;
  }

  async getDefaultBranch(owner: string, repo: string): Promise<string> {
    const repoMeta = await this.call<{ default_branch: string }>(`/repos/${owner}/${repo}`);
    return repoMeta.default_branch;
  }

  async getFile(owner: string, repo: string, path: string, ref?: string): Promise<GitHubFile> {
    const q = ref ? `?ref=${encodeURIComponent(ref)}` : "";
    const meta = await this.call<{ content: string; encoding: string; sha: string; path: string }>(
      `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}${q}`,
    );
    if (meta.encoding !== "base64") throw new Error(`Unexpected GitHub file encoding: ${meta.encoding}`);
    const content = Buffer.from(meta.content, "base64").toString("utf8");
    return { path: meta.path, content, sha: meta.sha };
  }

  async createBranch(owner: string, repo: string, branch: string, fromRef: string): Promise<void> {
    const srcRef = await this.call<{ object: { sha: string } }>(
      `/repos/${owner}/${repo}/git/ref/heads/${encodeURIComponent(fromRef)}`,
    );
    await this.call(`/repos/${owner}/${repo}/git/refs`, {
      method: "POST",
      body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: srcRef.object.sha }),
    });
  }

  async upsertFile(
    owner: string,
    repo: string,
    branch: string,
    path: string,
    content: string,
    message: string,
    sha?: string,
  ): Promise<void> {
    const body: Record<string, unknown> = {
      message,
      branch,
      content: Buffer.from(content, "utf8").toString("base64"),
    };
    if (sha) body.sha = sha;
    await this.call(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, {
      method: "PUT",
      body: JSON.stringify(body),
    });
  }

  async createPullRequest(
    owner: string,
    repo: string,
    opts: CreatePullRequestOpts,
  ): Promise<CreatedPullRequest> {
    const pr = await this.call<{ html_url: string; number: number }>(
      `/repos/${owner}/${repo}/pulls`,
      { method: "POST", body: JSON.stringify(opts) },
    );
    return { url: pr.html_url, number: pr.number };
  }
}

export function parseRepoSlug(slug: string): { owner: string; repo: string } {
  const m = slug.match(/^([^/\s]+)\/([^/\s]+?)(?:\.git)?$/);
  if (!m) throw new Error(`Invalid repo slug: expected "owner/repo", got "${slug}"`);
  return { owner: m[1], repo: m[2] };
}
