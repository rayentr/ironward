export type K8sSeverity = "critical" | "high" | "medium" | "low";

export interface K8sRule {
  id: string;
  severity: K8sSeverity;
  category:
    | "privilege"
    | "capability"
    | "secret"
    | "filesystem"
    | "network"
    | "resource"
    | "reliability"
    | "image"
    | "rbac";
  title: string;
  /** Regex checked against the full manifest content. */
  re: RegExp;
  /** True for a rule that matches the ABSENCE of something (a negative probe). */
  absence?: boolean;
  rationale: string;
  fix: string;
  /** Which manifest kinds this rule applies to. `workload` means anything with a PodSpec. */
  appliesTo: ReadonlyArray<"workload" | "any">;
}

const WORKLOAD = ["workload"] as const;
const ANY = ["any"] as const;

export const K8S_RULES: K8sRule[] = [
  // ──────────────────────────────────────────────────────────────
  // Privilege escalation
  // ──────────────────────────────────────────────────────────────
  {
    id: "k8s-run-as-root",
    severity: "high",
    category: "privilege",
    title: "Container runs as root (missing runAsNonRoot: true or runAsUser: 0)",
    re: /^\s*runAsUser\s*:\s*0\b/m,
    rationale: "Containers running as UID 0 give any process inside root privileges. A container escape via a kernel CVE becomes host root. runAsNonRoot: true plus a non-zero runAsUser forces the image to declare a user.",
    fix: "Under `securityContext:` set `runAsNonRoot: true` and `runAsUser: 10001` (or any non-zero UID your image supports).",
    appliesTo: WORKLOAD,
  },
  {
    id: "k8s-privileged-true",
    severity: "critical",
    category: "privilege",
    title: "Container has securityContext.privileged: true",
    re: /^\s*privileged\s*:\s*true\b/m,
    rationale: "privileged: true disables nearly every isolation mechanism — all capabilities granted, seccomp/AppArmor off, full device access. It is effectively root on the node.",
    fix: "Remove `privileged: true`. If a specific capability is actually needed, add it explicitly via `securityContext.capabilities.add` with a minimal list.",
    appliesTo: WORKLOAD,
  },
  {
    id: "k8s-allow-privilege-escalation",
    severity: "high",
    category: "privilege",
    title: "Container allows privilege escalation (allowPrivilegeEscalation: true)",
    re: /^\s*allowPrivilegeEscalation\s*:\s*true\b/m,
    rationale: "allowPrivilegeEscalation: true permits setuid binaries (e.g. /usr/bin/sudo, /bin/mount) to gain capabilities the parent process doesn't have — a well-known container breakout aid.",
    fix: "Set `allowPrivilegeEscalation: false` under the container's `securityContext`.",
    appliesTo: WORKLOAD,
  },
  {
    id: "k8s-host-network",
    severity: "high",
    category: "network",
    title: "Pod uses hostNetwork: true",
    re: /^\s*hostNetwork\s*:\s*true\b/m,
    rationale: "hostNetwork: true shares the node's network namespace with the pod. It can bind any port on the host, sniff other pods' traffic, and bypass NetworkPolicy entirely.",
    fix: "Remove `hostNetwork: true`. Expose services via a Service object; only specific system daemons (CNI, kube-proxy) legitimately need host networking.",
    appliesTo: WORKLOAD,
  },
  {
    id: "k8s-host-pid",
    severity: "high",
    category: "privilege",
    title: "Pod uses hostPID: true",
    re: /^\s*hostPID\s*:\s*true\b/m,
    rationale: "hostPID: true lets the container see and signal every process on the node — including kubelet and other tenants' workloads. Trivial lateral movement primitive.",
    fix: "Remove `hostPID: true`. If you need to inspect host processes, use a dedicated monitoring DaemonSet with read-only scope.",
    appliesTo: WORKLOAD,
  },
  {
    id: "k8s-host-ipc",
    severity: "medium",
    category: "privilege",
    title: "Pod uses hostIPC: true",
    re: /^\s*hostIPC\s*:\s*true\b/m,
    rationale: "hostIPC: true shares the host's IPC namespace, letting the container read shared memory segments and semaphores of host processes.",
    fix: "Remove `hostIPC: true`. Containers almost never need host IPC.",
    appliesTo: WORKLOAD,
  },

  // ──────────────────────────────────────────────────────────────
  // Capabilities / filesystem
  // ──────────────────────────────────────────────────────────────
  {
    id: "k8s-sensitive-capability-added",
    severity: "critical",
    category: "capability",
    title: "Container adds a sensitive Linux capability",
    re: /(?:add\s*:\s*\[[^\]]*\b|^\s*-\s*["']?)(?:SYS_ADMIN|NET_ADMIN|SYS_MODULE|SYS_PTRACE|SYS_BOOT|ALL)\b/m,
    rationale: "SYS_ADMIN alone is close to root — it enables mount, namespace manipulation, and many container-escape techniques. NET_ADMIN, SYS_MODULE, SYS_PTRACE, SYS_BOOT, and ALL are similarly dangerous.",
    fix: "Drop ALL capabilities and add back only the narrow one you need: `capabilities: { drop: [ALL], add: [NET_BIND_SERVICE] }` (for binding <1024 only).",
    appliesTo: WORKLOAD,
  },
  {
    id: "k8s-no-readonly-root-filesystem",
    severity: "low",
    category: "filesystem",
    title: "Container filesystem is writable (no readOnlyRootFilesystem: true)",
    re: /^\s*readOnlyRootFilesystem\s*:\s*true\b/m,
    absence: true,
    rationale: "A writable root filesystem lets an attacker drop payloads, modify binaries, or persist via cron/systemd inside the container. Read-only root + a narrow `emptyDir` volume for truly writable paths is the hardened pattern.",
    fix: "Add `readOnlyRootFilesystem: true` under the container's `securityContext`. Mount `emptyDir` volumes at any path that must be writable (e.g. /tmp, /var/run).",
    appliesTo: WORKLOAD,
  },

  // ──────────────────────────────────────────────────────────────
  // Secrets handling
  // ──────────────────────────────────────────────────────────────
  {
    id: "k8s-secret-in-env-literal",
    severity: "high",
    category: "secret",
    title: "Possible literal secret in env value (use valueFrom: secretKeyRef)",
    re: /\bvalue\s*:\s*["']?(?:[A-Za-z0-9+/=]{20,}|sk-ant-[A-Za-z0-9_-]+|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36})/,
    rationale: "Hardcoded secrets under `env[].value` end up in every checked-in manifest and in `kubectl get pod -o yaml` for anyone with read access. Rotating them means editing every manifest.",
    fix: "Move the value into a Secret and reference it: `valueFrom: { secretKeyRef: { name: my-secret, key: token } }`. Manage the Secret via sealed-secrets, SOPS, or an external secret store.",
    appliesTo: WORKLOAD,
  },

  // ──────────────────────────────────────────────────────────────
  // Resource safety & reliability
  // ──────────────────────────────────────────────────────────────
  {
    id: "k8s-no-resource-limits",
    severity: "medium",
    category: "resource",
    title: "PodSpec missing resources.limits",
    re: /^\s*limits\s*:/m,
    absence: true,
    rationale: "Without CPU/memory limits, one runaway pod can starve every other workload on the node — a cheap denial-of-service primitive, and a common cause of noisy-neighbor incidents.",
    fix: "Under each container add `resources: { requests: { cpu: 100m, memory: 128Mi }, limits: { cpu: 500m, memory: 512Mi } }` sized to your workload.",
    appliesTo: WORKLOAD,
  },
  {
    id: "k8s-no-liveness-probe",
    severity: "low",
    category: "reliability",
    title: "Container has no livenessProbe",
    re: /^\s*livenessProbe\s*:/m,
    absence: true,
    rationale: "Without a liveness probe, a deadlocked or wedged process keeps receiving traffic until it is noticed manually — an availability and detection gap.",
    fix: "Add a `livenessProbe` (httpGet, tcpSocket, or exec) with sane `initialDelaySeconds` and `periodSeconds` values.",
    appliesTo: WORKLOAD,
  },
  {
    id: "k8s-no-readiness-probe",
    severity: "low",
    category: "reliability",
    title: "Container has no readinessProbe",
    re: /^\s*readinessProbe\s*:/m,
    absence: true,
    rationale: "Without a readiness probe, the Service sends traffic to pods during slow startup or transient failure windows, producing user-visible errors.",
    fix: "Add a `readinessProbe` pointing at a fast health endpoint or port that only passes once the app is truly ready.",
    appliesTo: WORKLOAD,
  },

  // ──────────────────────────────────────────────────────────────
  // Image hygiene
  // ──────────────────────────────────────────────────────────────
  {
    id: "k8s-image-latest-tag",
    severity: "medium",
    category: "image",
    title: "Container image uses :latest or has no tag",
    re: /^\s*image\s*:\s*["']?(?!scratch\b)[\w.\/-]+(?::latest\b|(?!\s*[:@]))["']?\s*(?:#.*)?$/m,
    rationale: ":latest and untagged images are mutable — the same manifest pulls different bits tomorrow. Supply-chain substitutions and silent behavior changes slip in undetected.",
    fix: "Pin to an immutable reference: `image: myrepo/app:1.4.2` (min) or `image: myrepo/app@sha256:abcd…` (best).",
    appliesTo: WORKLOAD,
  },

  // ──────────────────────────────────────────────────────────────
  // Service account / RBAC
  // ──────────────────────────────────────────────────────────────
  {
    id: "k8s-default-service-account",
    severity: "medium",
    category: "rbac",
    title: "Workload uses the default ServiceAccount",
    re: /^\s*serviceAccountName\s*:\s*["']?default["']?\s*$/m,
    rationale: "The `default` ServiceAccount in each namespace accumulates permissions over time and is shared across unrelated pods. Compromise of one pod equals compromise of every other pod that shares it.",
    fix: "Create a purpose-built ServiceAccount per workload with only the RBAC rules it actually needs, and set `serviceAccountName: my-app-sa`.",
    appliesTo: WORKLOAD,
  },
  {
    id: "k8s-automount-service-account-token",
    severity: "low",
    category: "rbac",
    title: "automountServiceAccountToken: true (explicit)",
    re: /^\s*automountServiceAccountToken\s*:\s*true\b/m,
    rationale: "Mounting the SA token into /var/run/secrets gives every process inside the container an API credential. If the pod doesn't call the Kubernetes API, the token is a free lateral-movement primitive for an attacker who lands inside.",
    fix: "Set `automountServiceAccountToken: false` at the pod level (or on the ServiceAccount) unless the workload genuinely talks to the API server.",
    appliesTo: WORKLOAD,
  },
];
