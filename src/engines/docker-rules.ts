export type DockerSeverity = "critical" | "high" | "medium" | "low";

export interface DockerRule {
  id: string;
  severity: DockerSeverity;
  category:
    | "privilege"
    | "secret"
    | "supply-chain"
    | "network"
    | "filesystem"
    | "image"
    | "build"
    | "compose";
  title: string;
  /** Regex checked against the full file content. */
  re: RegExp;
  /** True for a rule that matches the ABSENCE of something (an anti-pattern we check with a negative probe). */
  absence?: boolean;
  rationale: string;
  fix: string;
  /** Which file types this rule applies to. */
  appliesTo: ReadonlyArray<"dockerfile" | "compose">;
}

const DOCKERFILE = ["dockerfile"] as const;
const COMPOSE = ["compose"] as const;
const BOTH = ["dockerfile", "compose"] as const;

export const DOCKER_RULES: DockerRule[] = [
  // ──────────────────────────────────────────────────────────────
  // Privilege
  // ──────────────────────────────────────────────────────────────
  {
    id: "no-user-directive",
    severity: "high",
    category: "privilege",
    title: "Dockerfile runs as root (no USER directive)",
    re: /^USER\s+\w+/im,
    absence: true,
    rationale: "A container without a non-root USER runs processes as UID 0. If an attacker escapes, they have root inside the container — and a kernel CVE away from host root.",
    fix: "Add `RUN adduser --system --no-create-home --uid 10001 app && USER app` before the final CMD/ENTRYPOINT.",
    appliesTo: DOCKERFILE,
  },
  {
    id: "compose-privileged-mode",
    severity: "critical",
    category: "privilege",
    title: "docker-compose service uses privileged: true",
    re: /^\s*privileged\s*:\s*true\b/im,
    rationale: "privileged: true gives the container full access to every device on the host and disables seccomp/AppArmor. Equivalent to running as root on the host.",
    fix: "Remove `privileged: true`. If you need specific capabilities, use `cap_add` with a minimal, documented list.",
    appliesTo: COMPOSE,
  },
  {
    id: "compose-sensitive-mount",
    severity: "critical",
    category: "filesystem",
    title: "docker-compose mounts a sensitive host path",
    re: /^\s*-\s*['"]?(?:\/etc|\/var\/run\/docker\.sock|\/proc|\/sys|\/root)\b[^'"\n]*['"]?:/m,
    rationale: "Mounting /var/run/docker.sock gives container the ability to start privileged containers on the host — a full host compromise primitive. /etc, /proc, /sys, and /root are similarly dangerous.",
    fix: "Do not mount Docker-in-Docker via the host socket. For read access to /etc/hostname etc., copy only what you need at build time.",
    appliesTo: COMPOSE,
  },
  {
    id: "compose-host-network",
    severity: "high",
    category: "network",
    title: "docker-compose uses network_mode: host",
    re: /^\s*network_mode\s*:\s*['"]?host['"]?/im,
    rationale: "host networking bypasses Docker's network namespace — the container shares the host's network stack and can bind to any port, including unprivileged ones that would normally be isolated.",
    fix: "Use a bridge or overlay network. Explicit port publishing via `ports:` is almost always what you want.",
    appliesTo: COMPOSE,
  },

  // ──────────────────────────────────────────────────────────────
  // Secrets
  // ──────────────────────────────────────────────────────────────
  {
    id: "secret-in-env",
    severity: "critical",
    category: "secret",
    title: "Possible secret in ENV directive",
    re: /^ENV\s+(?:[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|APIKEY|AUTH|DSN)[A-Z_]*)\s*[=\s]\s*(?:['"]?)[A-Za-z0-9_+/=\-]{12,}/im,
    rationale: "Secrets baked into ENV are readable by `docker inspect` and persist in every image layer — anyone with pull access to the registry gets them.",
    fix: "Pass secrets at runtime via `--env-file`, Docker secrets (swarm), or orchestrator-level secret stores (K8s Secret, Vault, AWS Secrets Manager).",
    appliesTo: DOCKERFILE,
  },
  {
    id: "secret-in-arg",
    severity: "high",
    category: "secret",
    title: "Possible secret in ARG directive (leaks in image history)",
    re: /^ARG\s+(?:[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|APIKEY)[A-Z_]*)\s*=\s*(?:['"]?)[A-Za-z0-9_+/=\-]{12,}/im,
    rationale: "ARG values appear in `docker history` even when unset in the final image — a classic build-time secret leak vector.",
    fix: "Use BuildKit secret mounts: `RUN --mount=type=secret,id=npmrc cat /run/secrets/npmrc`. Never pass real secret values in ARG defaults.",
    appliesTo: DOCKERFILE,
  },
  {
    id: "compose-secret-in-environment",
    severity: "high",
    category: "secret",
    title: "docker-compose hardcodes a secret in `environment:`",
    re: /^\s*(?:-\s+)?(?:[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|DSN|URL)[A-Z_]*)\s*(?::|=)\s*(?!['"]?\$\{?)['"]?[A-Za-z0-9_+/=:@.\/\-]{12,}['"]?\s*$/im,
    rationale: "Hardcoded secrets in docker-compose.yml get committed to source control on every change.",
    fix: "Reference env vars with `${VAR}` and load values from an external .env file or your secret manager.",
    appliesTo: COMPOSE,
  },

  // ──────────────────────────────────────────────────────────────
  // Supply chain / image pinning
  // ──────────────────────────────────────────────────────────────
  {
    id: "latest-tag",
    severity: "medium",
    category: "supply-chain",
    title: "Base image uses :latest tag (unpinned)",
    re: /^FROM\s+[\w./-]+:latest\b/im,
    rationale: ":latest is mutable — the same Dockerfile builds a different image on different days. Supply-chain attacks and silent behavior changes slip in unnoticed.",
    fix: "Pin to a specific version or (better) a SHA256 digest: `FROM node:20.11@sha256:abcd...`.",
    appliesTo: DOCKERFILE,
  },
  {
    id: "no-base-image-tag",
    severity: "medium",
    category: "supply-chain",
    title: "Base image has no tag (implicit :latest)",
    re: /^FROM\s+(?!scratch\b)([\w./-]+)(?::|@)?\s*(?:AS\s+\w+)?\s*$/im,
    rationale: "No tag == :latest, same supply-chain risk.",
    fix: "Pin to `image:MAJOR.MINOR` minimum, ideally with a SHA digest.",
    appliesTo: DOCKERFILE,
  },
  {
    id: "copy-everything",
    severity: "medium",
    category: "build",
    title: "COPY . . ships everything — check for secret-containing files",
    re: /^COPY\s+(?:--[\w=-]+\s+)*\.\s+\.\s*$/im,  // ironward-ignore
    rationale: "`COPY . .` happily copies `.env`, `.git`, node_modules, local build artifacts, SSH keys, and editor backup files into the image.",
    fix: "Add a strict `.dockerignore` (at minimum: `.env*`, `.git`, `node_modules`, `*.pem`, `*.key`, `id_rsa*`). Prefer copying explicit paths.",
    appliesTo: DOCKERFILE,
  },
  {
    id: "add-remote-url",
    severity: "medium",
    category: "supply-chain",
    title: "ADD from a remote URL — use COPY + verified download instead",
    re: /^ADD\s+https?:\/\//im,
    rationale: "ADD silently downloads remote URLs with no signature or checksum check. A compromised or MITM'd endpoint ships whatever it wants into your image.",
    fix: "Use `RUN curl -fsSL <url> -o file && sha256sum -c file.sha256` or `COPY` a vendored copy. Prefer pinning to a digest.",
    appliesTo: DOCKERFILE,
  },
  {
    id: "curl-pipe-shell",
    severity: "high",
    category: "supply-chain",
    title: "`curl | sh` or `wget | sh` pattern in RUN",
    re: /^RUN\s+[^\n]*(?:curl|wget)\s+[^\n]*\|\s*(?:sh|bash)/im,
    rationale: "Piping an unverified remote script into a shell gives whoever controls that URL code execution during your image build.",
    fix: "Download to a file, verify a SHA256, then execute. Or vendor the install script into your repo and COPY it in.",
    appliesTo: DOCKERFILE,
  },

  // ──────────────────────────────────────────────────────────────
  // Image hygiene
  // ──────────────────────────────────────────────────────────────
  {
    id: "no-healthcheck",
    severity: "low",
    category: "image",
    title: "No HEALTHCHECK defined",
    re: /^HEALTHCHECK\s+/im,
    absence: true,
    rationale: "Without a healthcheck, orchestrators can't tell a deadlocked container from a healthy one. Not a direct security vulnerability, but a reliability gap that hides compromise.",
    fix: "Add `HEALTHCHECK --interval=30s CMD curl -f http://localhost:3000/health || exit 1` (or your app's equivalent).",
    appliesTo: DOCKERFILE,
  },
  {
    id: "apt-no-clean",
    severity: "low",
    category: "image",
    title: "apt-get install without cleanup bloats image & may leak cache",
    re: /RUN\s+[^\n]*apt-get\s+install(?![^\n]*rm\s+-rf\s+\/var\/lib\/apt\/lists)/im,
    rationale: "Leaving /var/lib/apt/lists around wastes tens of MB per layer and can leak package-index metadata.",
    fix: "End the RUN with `&& rm -rf /var/lib/apt/lists/*` (or use `--no-install-recommends` + multi-stage builds).",
    appliesTo: DOCKERFILE,
  },

  // ──────────────────────────────────────────────────────────────
  // Exposed ports
  // ──────────────────────────────────────────────────────────────
  {
    id: "expose-ssh",
    severity: "high",
    category: "network",
    title: "Container exposes SSH (port 22)",
    re: /^EXPOSE\s+(?:[0-9/]+\s+)*(?:22|22\/tcp)\b/im,  // ironward-ignore
    rationale: "SSH inside a container is almost always an anti-pattern — it duplicates host access control and tends to ship with default credentials or static keys.",
    fix: "Remove the SSH daemon. Use `docker exec` or `kubectl exec` for interactive access.",
    appliesTo: DOCKERFILE,
  },
  {
    id: "expose-db-ports",
    severity: "medium",
    category: "network",
    title: "Container EXPOSEs a database port directly",
    re: /^EXPOSE\s+(?:[0-9/]+\s+)*(?:3306|5432|27017|6379|9200|1433|11211)(?:\/tcp)?\b/im,  // ironward-ignore
    rationale: "Exposing DB ports at the image level encourages direct public mapping — auth misconfig turns into a public-internet breach quickly.",
    fix: "Keep DB traffic on an internal Docker network. Publish only your HTTP entry point.",
    appliesTo: DOCKERFILE,
  },
];
