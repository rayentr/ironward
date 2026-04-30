export type InfraSeverity = "critical" | "high" | "medium" | "low";

export type InfraFileKind = "terraform" | "cloudformation";

export interface InfraRule {
  id: string;
  severity: InfraSeverity;
  category:
    | "access-control"
    | "network"
    | "encryption"
    | "secret"
    | "logging"
    | "resilience"
    | "identity"
    | "state";
  title: string;
  /** Regex checked against the full file content. */
  re: RegExp;
  /** True for a rule that matches the ABSENCE of something. */
  absence?: boolean;
  rationale: string;
  fix: string;
  /** Which file types this rule applies to. */
  appliesTo: ReadonlyArray<InfraFileKind>;
}

const TERRAFORM = ["terraform"] as const;
const CFN = ["cloudformation"] as const;

export const INFRA_RULES: InfraRule[] = [
  // ──────────────────────────────────────────────────────────────
  // AWS — Terraform — S3
  // ──────────────────────────────────────────────────────────────
  {
    id: "tf-s3-bucket-public-read",
    severity: "critical",
    category: "access-control",
    title: "S3 bucket ACL is public-read or public-read-write",
    re: /resource\s+"aws_s3_bucket(?:_acl)?"[^{]*\{[^}]*?\bacl\s*=\s*"(?:public-read|public-read-write)"/is,
    rationale: "Public ACLs expose every object in the bucket to the entire internet. This is the canonical root cause of S3-leak headlines (voter rolls, resumes, customer data).",
    fix: "Set `acl = \"private\"` and manage access via IAM policies or a dedicated bucket policy. Enable `aws_s3_bucket_public_access_block` with all four blocks set to true.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-s3-bucket-no-versioning",
    severity: "medium",
    category: "resilience",
    title: "S3 bucket has versioning explicitly disabled",
    re: /resource\s+"aws_s3_bucket(?:_versioning)?"[^{]*\{[^}]*?versioning(?:_configuration)?\s*\{[^}]*?(?:status\s*=\s*"Suspended"|enabled\s*=\s*false)/is,
    rationale: "Without versioning, an accidental overwrite or ransomware event is unrecoverable. Versioning is the cheapest insurance S3 offers.",
    fix: "Enable versioning: `resource \"aws_s3_bucket_versioning\" \"this\" { ... versioning_configuration { status = \"Enabled\" } }`.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-s3-bucket-no-encryption",
    severity: "high",
    category: "encryption",
    title: "S3 bucket has no server-side encryption configuration",
    re: /(?:server_side_encryption_configuration|aws_s3_bucket_server_side_encryption_configuration)/i,
    absence: true,
    rationale: "S3 SSE-S3 is free and on-by-default for new buckets, but Terraform-managed buckets without an explicit SSE config rely on account-level defaults that can silently change.",
    fix: "Declare `aws_s3_bucket_server_side_encryption_configuration` with `sse_algorithm = \"AES256\"` (or `aws:kms` for a CMK).",
    appliesTo: TERRAFORM,
  },

  // ──────────────────────────────────────────────────────────────
  // AWS — Terraform — Security Groups
  // ──────────────────────────────────────────────────────────────
  {
    id: "tf-sg-ingress-0-0-0-0-ssh",
    severity: "critical",
    category: "network",
    title: "Security group opens SSH (port 22) to 0.0.0.0/0",
    re: /ingress\s*\{[^}]*?from_port\s*=\s*22[^}]*?to_port\s*=\s*22[^}]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/is,
    rationale: "Exposing SSH to the public internet invites continuous credential-stuffing and 0-day scans. One stolen key or weak password away from full host compromise.",
    fix: "Restrict `cidr_blocks` to your bastion/VPN range, or move to AWS Systems Manager Session Manager (no inbound ports needed).",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-sg-ingress-0-0-0-0-rdp",
    severity: "critical",
    category: "network",
    title: "Security group opens RDP (port 3389) to 0.0.0.0/0",
    re: /ingress\s*\{[^}]*?from_port\s*=\s*3389[^}]*?to_port\s*=\s*3389[^}]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/is,
    rationale: "Public RDP is a primary ransomware entry vector. BlueKeep-class CVEs turn an open 3389 into a worm target.",
    fix: "Restrict to a VPN CIDR. Prefer AWS SSM Session Manager or Azure Bastion over exposing RDP at all.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-sg-ingress-0-0-0-0-all-ports",
    severity: "critical",
    category: "network",
    title: "Security group opens ALL ports to 0.0.0.0/0",
    re: /ingress\s*\{[^}]*?from_port\s*=\s*0[^}]*?to_port\s*=\s*65535[^}]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/is,
    rationale: "An all-ports-open rule is effectively no firewall. Every service that binds to the instance is on the public internet.",
    fix: "Scope ingress to the specific ports your workload uses and the specific CIDRs you trust.",
    appliesTo: TERRAFORM,
  },

  // ──────────────────────────────────────────────────────────────
  // AWS — Terraform — RDS
  // ──────────────────────────────────────────────────────────────
  {
    id: "tf-rds-publicly-accessible",
    severity: "critical",
    category: "network",
    title: "RDS instance is publicly accessible",
    re: /resource\s+"aws_db_instance"[^{]*\{[^}]*?publicly_accessible\s*=\s*true/is,
    rationale: "A public RDS endpoint is only one weak password or SG misconfig away from exposing production data. Database engines are chronic CVE targets too.",
    fix: "Set `publicly_accessible = false`. Connect via a private subnet, a bastion, or a VPN. Use IAM DB auth where possible.",
    appliesTo: TERRAFORM,
  },

  // ──────────────────────────────────────────────────────────────
  // AWS — Terraform — IAM
  // ──────────────────────────────────────────────────────────────
  {
    id: "tf-iam-policy-star-action",
    severity: "high",
    category: "identity",
    title: "IAM policy grants Action=\"*\" on Resource=\"*\"",
    re: /"Action"\s*:\s*"\*"[^}]{0,400}?"Resource"\s*:\s*"\*"|"Resource"\s*:\s*"\*"[^}]{0,400}?"Action"\s*:\s*"\*"/is,
    rationale: "Action=* + Resource=* is administrator-equivalent. Any credential that can assume this role owns the account.",
    fix: "Replace with the specific actions the workload actually needs. Use AWS-provided managed policies as a starting point, then scope further.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-iam-assume-role-star",
    severity: "critical",
    category: "identity",
    title: "IAM role trust policy allows Principal=\"*\"",
    re: /assume_role_policy[\s\S]{0,400}?"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*"\s*\})/i,
    rationale: "An assume-role trust policy with Principal=* lets any AWS account (and anyone who can create one) assume the role. Immediate account takeover primitive.",
    fix: "Set Principal to a specific AWS account ARN or federated identity provider. Add a `sts:ExternalId` condition for cross-account trust.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-lambda-admin-role",
    severity: "medium",
    category: "identity",
    title: "Lambda uses an AdministratorAccess-attached role",
    re: /policy_arn\s*=\s*"arn:aws:iam::aws:policy\/AdministratorAccess"/i,
    rationale: "Giving a Lambda the AdministratorAccess policy means any RCE in the function is an account takeover. Lambdas are a big attack surface (deps, event payloads).",
    fix: "Attach a scoped policy with only the actions this function needs — S3 GetObject on one bucket, DynamoDB on one table, etc.",
    appliesTo: TERRAFORM,
  },

  // ──────────────────────────────────────────────────────────────
  // AWS — Terraform — Logging / EBS
  // ──────────────────────────────────────────────────────────────
  {
    id: "tf-cloudtrail-disabled",
    severity: "medium",
    category: "logging",
    title: "CloudTrail has logging disabled",
    re: /resource\s+"aws_cloudtrail"[^{]*\{[^}]*?enable_logging\s*=\s*false/is,
    rationale: "CloudTrail is the audit log of record for AWS. Disabling it blinds incident response and kills every compliance story (SOC2, ISO, PCI).",
    fix: "Remove `enable_logging = false` (default is true). Ensure `is_multi_region_trail = true` on at least one trail per account.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-unencrypted-ebs",
    severity: "high",
    category: "encryption",
    title: "EBS volume is unencrypted",
    re: /resource\s+"aws_ebs_volume"[^{]*\{[^}]*?encrypted\s*=\s*false/is,
    rationale: "Unencrypted EBS volumes leak data if a snapshot is accidentally shared or an account is compromised. Encryption is a one-flag change with negligible cost.",
    fix: "Set `encrypted = true`. Ideally specify `kms_key_id` for a CMK you control. Enable EBS encryption by default at the account level.",
    appliesTo: TERRAFORM,
  },

  // ──────────────────────────────────────────────────────────────
  // AWS — Terraform — Credentials / State
  // ──────────────────────────────────────────────────────────────
  {
    id: "tf-hardcoded-aws-creds",
    severity: "critical",
    category: "secret",
    title: "Hardcoded AWS credentials in Terraform",
    re: /\b(?:access_key|secret_key)\s*=\s*"(?:AKIA[0-9A-Z]{16}|[A-Za-z0-9/+=]{40})"/,
    rationale: "AWS credentials committed to Terraform source end up in git history forever. Anyone with repo read gets root.",
    fix: "Remove the literal. Use the provider's default credential chain (env vars, IAM role, SSO). If you must inject, use `var.aws_access_key` sourced from a secret store.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-local-state-no-encryption",
    severity: "medium",
    category: "state",
    title: "Terraform uses local backend (state at rest is unencrypted)",
    re: /terraform\s*\{[^}]*?backend\s+"local"/is,
    rationale: "Local state files contain every secret Terraform has ever rendered — DB passwords, access keys, private keys — in plaintext JSON on disk and in any backup that touches the repo.",
    fix: "Switch to a remote backend with encryption and locking: `backend \"s3\"` (with `encrypt = true` + DynamoDB lock) or Terraform Cloud.",
    appliesTo: TERRAFORM,
  },

  // ──────────────────────────────────────────────────────────────
  // GCP
  // ──────────────────────────────────────────────────────────────
  {
    id: "tf-gcs-all-users",
    severity: "critical",
    category: "access-control",
    title: "GCS bucket grants access to allUsers / allAuthenticatedUsers",  // ironward-ignore
    re: /(?:role_entity\s*=\s*\[\s*"READER:allUsers"|member\s*=\s*"all(?:Authenticated)?Users"|members\s*=\s*\[\s*"all(?:Authenticated)?Users")/i,  // ironward-ignore
    rationale: "`allUsers` is the GCP equivalent of \"public internet.\" `allAuthenticatedUsers` is any Google account holder on earth — not much better.",  // ironward-ignore
    fix: "Grant access to specific service accounts, groups, or domains. Turn on Uniform Bucket-Level Access and enforce Org Policy `iam.allowedPolicyMemberDomains`.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-gcp-firewall-open-all",
    severity: "high",
    category: "network",
    title: "GCP firewall allows 0.0.0.0/0 to all ports",
    re: /resource\s+"google_compute_firewall"[^{]*\{[\s\S]*?source_ranges\s*=\s*\[\s*"0\.0\.0\.0\/0"/i,
    rationale: "A 0.0.0.0/0 firewall rule without tight port scoping puts every service reachable from the VM on the public internet.",
    fix: "Scope `source_ranges` to specific CIDRs (load balancer, IAP, VPN). Prefer Identity-Aware Proxy for admin access.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-gke-legacy-auth",
    severity: "critical",
    category: "identity",
    title: "GKE cluster enables legacy basic-auth (master_auth username)",
    re: /resource\s+"google_container_cluster"[^{]*\{[\s\S]*?master_auth\s*\{[^}]*?username\s*=/i,
    rationale: "Basic auth on the GKE control plane predates modern IAM. A leaked username/password gives kube-apiserver access. Google deprecated this for a reason.",
    fix: "Remove the `master_auth { username = ... }` block. Use GKE IAM + Workload Identity. Set `master_auth { client_certificate_config { issue_client_certificate = false } }`.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-gcp-public-vm",
    severity: "medium",
    category: "network",
    title: "GCE instance assigns a public external IP",
    re: /resource\s+"google_compute_instance"[^{]*\{[\s\S]*?network_interface\s*\{[\s\S]*?access_config\s*\{/i,
    rationale: "An empty `access_config {}` block gives the VM an ephemeral public IP. Most workloads don't need one; keeping them private shrinks the attack surface.",
    fix: "Remove the `access_config` block. Use Cloud NAT for outbound internet and IAP for inbound SSH.",
    appliesTo: TERRAFORM,
  },

  // ──────────────────────────────────────────────────────────────
  // Azure
  // ──────────────────────────────────────────────────────────────
  {
    id: "tf-azure-storage-public-blob",
    severity: "high",
    category: "access-control",
    title: "Azure storage account explicitly allows public blob access",
    re: /resource\s+"azurerm_storage_account"[^{]*\{[\s\S]*?allow_blob_public_access\s*=\s*true/i,
    rationale: "Even if individual containers are private, `allow_blob_public_access = true` keeps the door open for someone to later flip a container to public without further review.",
    fix: "Set `allow_blob_public_access = false` at the account level. Grant access via SAS, RBAC, or private endpoints.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-azure-nsg-open-all",
    severity: "high",
    category: "network",
    title: "Azure NSG rule allows inbound from any source",
    re: /resource\s+"azurerm_network_security_rule"[^{]*\{[\s\S]*?source_address_prefix\s*=\s*"\*"[\s\S]*?access\s*=\s*"Allow"[\s\S]*?direction\s*=\s*"Inbound"|resource\s+"azurerm_network_security_rule"[^{]*\{[\s\S]*?direction\s*=\s*"Inbound"[\s\S]*?access\s*=\s*"Allow"[\s\S]*?source_address_prefix\s*=\s*"\*"/i,
    rationale: "`source_address_prefix = \"*\"` on an inbound Allow rule is Azure's equivalent of 0.0.0.0/0. Same public-internet exposure.",
    fix: "Set `source_address_prefix` to a specific CIDR, service tag (e.g. `VirtualNetwork`), or application security group.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-azure-sql-public-network",
    severity: "high",
    category: "network",
    title: "Azure SQL server allows public network access",
    re: /resource\s+"azurerm_mssql_server"[^{]*\{[\s\S]*?public_network_access_enabled\s*=\s*true/i,
    rationale: "Putting a SQL server on the public internet exposes it to credential-stuffing and engine CVEs. Azure offers Private Link for a reason.",
    fix: "Set `public_network_access_enabled = false`. Use a Private Endpoint or VNet service endpoint for application access.",
    appliesTo: TERRAFORM,
  },
  {
    id: "tf-azure-keyvault-no-soft-delete",
    severity: "low",
    category: "resilience",
    title: "Azure Key Vault has short or missing soft-delete retention",
    re: /resource\s+"azurerm_key_vault"[^{]*\{[\s\S]*?soft_delete_retention_days\s*=\s*(?:[0-6])\b/i,
    rationale: "A short soft-delete window (< 7 days) means an accidental or malicious deletion of secrets is unrecoverable after the window closes.",
    fix: "Set `soft_delete_retention_days = 90` (the Azure default) and `purge_protection_enabled = true` for production vaults.",
    appliesTo: TERRAFORM,
  },

  // ──────────────────────────────────────────────────────────────
  // General
  // ──────────────────────────────────────────────────────────────
  {
    id: "tf-hardcoded-secret",
    severity: "high",
    category: "secret",
    title: "Hardcoded secret-looking value in Terraform attribute",
    re: /\b(?:password|api_key|apikey|token|secret)\s*=\s*"(?!(?:CHANGE_?ME|TODO|FIXME|REPLACE_?ME|EXAMPLE|\$\{)|[^"]{0,11}")(?!.*(?:var\.|data\.|local\.))([A-Za-z0-9_+/=@.\-]{12,})"/i,
    rationale: "Passwords and API keys committed to Terraform live in git history forever and in every state backup.",
    fix: "Reference `var.db_password` (set via `TF_VAR_db_password` env var or a secret manager data source). Never literal-quote real credentials.",
    appliesTo: TERRAFORM,
  },

  // ──────────────────────────────────────────────────────────────
  // CloudFormation
  // ──────────────────────────────────────────────────────────────
  {
    id: "cfn-s3-public-read",
    severity: "critical",
    category: "access-control",
    title: "CloudFormation S3 bucket has PublicRead ACL",
    re: /Type\s*:\s*["']?AWS::S3::Bucket["']?[\s\S]{0,600}?AccessControl\s*:\s*["']?(?:PublicRead|PublicReadWrite)["']?/i,
    rationale: "Public ACLs expose every object in the bucket to the internet.",
    fix: "Remove `AccessControl` (defaults to private) or set it to `Private`. Add a `PublicAccessBlockConfiguration` with all four flags true.",
    appliesTo: CFN,
  },
  {
    id: "cfn-sg-open-ssh",
    severity: "critical",
    category: "network",
    title: "CloudFormation SG opens SSH (port 22) to 0.0.0.0/0",
    re: /Type\s*:\s*["']?AWS::EC2::SecurityGroup(?:Ingress)?["']?[\s\S]{0,600}?(?:CidrIp\s*:\s*["']?0\.0\.0\.0\/0["']?[\s\S]{0,200}?FromPort\s*:\s*["']?22["']?|FromPort\s*:\s*["']?22["']?[\s\S]{0,200}?CidrIp\s*:\s*["']?0\.0\.0\.0\/0["']?)/i,
    rationale: "Public SSH is a constant brute-force target. One weak key ends it.",
    fix: "Restrict `CidrIp` to a bastion/VPN range or switch to SSM Session Manager.",
    appliesTo: CFN,
  },
  {
    id: "cfn-rds-public",
    severity: "critical",
    category: "network",
    title: "CloudFormation RDS instance is publicly accessible",
    re: /Type\s*:\s*["']?AWS::RDS::DBInstance["']?[\s\S]{0,800}?PubliclyAccessible\s*:\s*["']?true["']?/i,
    rationale: "A public RDS endpoint is one password away from a data breach.",
    fix: "Set `PubliclyAccessible: false`. Put the DB in a private subnet; connect via bastion or VPN.",
    appliesTo: CFN,
  },
  {
    id: "cfn-iam-star",
    severity: "high",
    category: "identity",
    title: "CloudFormation IAM policy grants Action=\"*\" on Resource=\"*\"",
    re: /(?:Action\s*:\s*["']?\*["']?[\s\S]{0,400}?Resource\s*:\s*["']?\*["']?|"Action"\s*:\s*"\*"[\s\S]{0,400}?"Resource"\s*:\s*"\*")/i,
    rationale: "Star-star is administrator-equivalent. Any principal using this policy owns the account.",
    fix: "Enumerate the specific AWS actions and resource ARNs the workload needs.",
    appliesTo: CFN,
  },
];
