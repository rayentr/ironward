import { test } from "node:test";
import assert from "node:assert/strict";
import { CLOUD_SECURITY_RULES } from "../src/rules/cloud-security.ts";

function findingsFor(code: string, ruleId: string): Array<{ index: number }> {
  const rule = CLOUD_SECURITY_RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error("rule not found: " + ruleId);
  rule.re.lastIndex = 0;
  const out: Array<{ index: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = rule.re.exec(code)) !== null) {
    if (rule.negativePattern && rule.negativePattern.test(m[0])) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      continue;
    }
    out.push({ index: m.index });
    if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
  }
  return out;
}

const ruleById = (id: string) => CLOUD_SECURITY_RULES.find((r) => r.id === id);

// =============== cloud-aws-s3-public-acl ===============

// WHY: public-read on an S3 PutObject is the canonical S3 leak shape.
test("cloud-aws-s3-public-acl: ACL: 'public-read' is flagged", () => {
  const code = `s3.putObject({ Bucket: 'b', Key: 'k', ACL: 'public-read' });`;
  assert.ok(findingsFor(code, "cloud-aws-s3-public-acl").length >= 1);
});

// WHY: ACL 'private' is the safe default; must not fire.
test("cloud-aws-s3-public-acl: ACL: 'private' is NOT flagged", () => {
  const code = `s3.putObject({ Bucket: 'b', Key: 'k', ACL: 'private' });`;
  assert.equal(findingsFor(code, "cloud-aws-s3-public-acl").length, 0);
});

// WHY: severity + owasp must remain critical / A05 for the public-ACL rule.
test("cloud-aws-s3-public-acl: metadata is critical + A05", () => {
  const r = ruleById("cloud-aws-s3-public-acl")!;
  assert.equal(r.severity, "critical");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});

// =============== cloud-aws-iam-star-action ===============

// WHY: Action: "*" is the textbook over-privileged IAM policy.
test("cloud-aws-iam-star-action: Action: \"*\" is flagged", () => {
  const code = `{ "Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*" }`;
  assert.ok(findingsFor(code, "cloud-aws-iam-star-action").length >= 1);
});

// WHY: an enumerated action list is safe.
test("cloud-aws-iam-star-action: enumerated actions are NOT flagged", () => {
  const code = `{ "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*" }`;
  assert.equal(findingsFor(code, "cloud-aws-iam-star-action").length, 0);
});

// WHY: severity + owasp for IAM Action: "*".
test("cloud-aws-iam-star-action: metadata is high + A05", () => {
  const r = ruleById("cloud-aws-iam-star-action")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});

// =============== cloud-aws-iam-star-resource ===============

// WHY: Resource: "*" is the wildcard-resource bug we want flagged.
test("cloud-aws-iam-star-resource: Resource: \"*\" is flagged", () => {
  const code = `{ "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*" }`;
  assert.ok(findingsFor(code, "cloud-aws-iam-star-resource").length >= 1);
});

// WHY: a scoped ARN is the safe pattern.
test("cloud-aws-iam-star-resource: scoped ARN is NOT flagged", () => {
  const code = `{ "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*" }`;
  assert.equal(findingsFor(code, "cloud-aws-iam-star-resource").length, 0);
});

// WHY: severity + owasp for Resource: "*".
test("cloud-aws-iam-star-resource: metadata is high + A05", () => {
  const r = ruleById("cloud-aws-iam-star-resource")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});

// =============== cloud-aws-rds-publicly-accessible ===============

// WHY: PubliclyAccessible: true exposes RDS to the internet.
test("cloud-aws-rds-publicly-accessible: PubliclyAccessible: true is flagged", () => {
  const code = `{ "Type": "AWS::RDS::DBInstance", "Properties": { "PubliclyAccessible": true } }`;
  assert.ok(findingsFor(code, "cloud-aws-rds-publicly-accessible").length >= 1);
});

// WHY: a private RDS instance must not trip the rule.
test("cloud-aws-rds-publicly-accessible: PubliclyAccessible: false is NOT flagged", () => {
  const code = `{ "PubliclyAccessible": false }`;
  assert.equal(findingsFor(code, "cloud-aws-rds-publicly-accessible").length, 0);
});

// WHY: severity + owasp for public RDS.
test("cloud-aws-rds-publicly-accessible: metadata is critical + A05", () => {
  const r = ruleById("cloud-aws-rds-publicly-accessible")!;
  assert.equal(r.severity, "critical");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});

// =============== cloud-aws-sg-open-ssh ===============

// WHY: the canonical "SSH open to world" CFN/Terraform shape.
test("cloud-aws-sg-open-ssh: 0.0.0.0/0 with port 22 is flagged", () => {
  const code = `{ "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0" }`;
  assert.ok(findingsFor(code, "cloud-aws-sg-open-ssh").length >= 1);
});

// WHY: SSH restricted to a corporate CIDR is the safe pattern.
test("cloud-aws-sg-open-ssh: restricted CIDR is NOT flagged", () => {
  const code = `{ "FromPort": 22, "ToPort": 22, "CidrIp": "10.0.0.0/8" }`;
  assert.equal(findingsFor(code, "cloud-aws-sg-open-ssh").length, 0);
});

// WHY: severity + owasp for open SSH.
test("cloud-aws-sg-open-ssh: metadata is critical + A05", () => {
  const r = ruleById("cloud-aws-sg-open-ssh")!;
  assert.equal(r.severity, "critical");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});

// =============== cloud-aws-sg-open-rdp ===============

// WHY: the canonical "RDP open to world" shape.
test("cloud-aws-sg-open-rdp: 0.0.0.0/0 with port 3389 is flagged", () => {
  const code = `{ "FromPort": 3389, "ToPort": 3389, "CidrIp": "0.0.0.0/0" }`;
  assert.ok(findingsFor(code, "cloud-aws-sg-open-rdp").length >= 1);
});

// WHY: RDP restricted to a VPN CIDR is safe.
test("cloud-aws-sg-open-rdp: restricted CIDR is NOT flagged", () => {
  const code = `{ "FromPort": 3389, "ToPort": 3389, "CidrIp": "10.0.0.0/8" }`;
  assert.equal(findingsFor(code, "cloud-aws-sg-open-rdp").length, 0);
});

// WHY: severity + owasp for open RDP.
test("cloud-aws-sg-open-rdp: metadata is critical + A05", () => {
  const r = ruleById("cloud-aws-sg-open-rdp")!;
  assert.equal(r.severity, "critical");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});

// =============== cloud-gcp-bucket-allusers ===============

// WHY: allUsers binding is anonymous public read on a GCS bucket.
test("cloud-gcp-bucket-allusers: allUsers binding is flagged", () => {
  const code = `bindings: [{ role: 'roles/storage.objectViewer', members: ['allUsers'] }]`;
  assert.ok(findingsFor(code, "cloud-gcp-bucket-allusers").length >= 1);
});

// WHY: a service-account binding is the safe pattern.
test("cloud-gcp-bucket-allusers: serviceAccount binding is NOT flagged", () => {
  const code = `bindings: [{ role: 'roles/storage.objectViewer', members: ['serviceAccount:app@x.iam.gserviceaccount.com'] }]`;
  assert.equal(findingsFor(code, "cloud-gcp-bucket-allusers").length, 0);
});

// WHY: severity + owasp for GCS allUsers.
test("cloud-gcp-bucket-allusers: metadata is critical + A05", () => {
  const r = ruleById("cloud-gcp-bucket-allusers")!;
  assert.equal(r.severity, "critical");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});

// =============== cloud-azure-storage-public-blob ===============

// WHY: publicAccess: 'Blob' makes a container anonymously readable.
test("cloud-azure-storage-public-blob: publicAccess: 'Blob' is flagged", () => {
  const code = `{ name: 'data', publicAccess: 'Blob' }`;
  assert.ok(findingsFor(code, "cloud-azure-storage-public-blob").length >= 1);
});

// WHY: publicAccess: 'None' is the safe default.
test("cloud-azure-storage-public-blob: publicAccess: 'None' is NOT flagged", () => {
  const code = `{ name: 'data', publicAccess: 'None' }`;
  assert.equal(findingsFor(code, "cloud-azure-storage-public-blob").length, 0);
});

// WHY: severity + owasp for Azure public blob.
test("cloud-azure-storage-public-blob: metadata is high + A05", () => {
  const r = ruleById("cloud-azure-storage-public-blob")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});

// =============== cloud-aws-lambda-env-secrets ===============

// WHY: Lambda env vars containing SECRET/PASSWORD are visible to anyone with
// lambda:GetFunctionConfiguration and end up in plaintext state files.
test("cloud-aws-lambda-env-secrets: Environment.Variables with API_KEY is flagged", () => {
  const code = `{ "Environment": { "Variables": { "STRIPE_API_KEY": "sk_live_xxx" } } }`;
  assert.ok(findingsFor(code, "cloud-aws-lambda-env-secrets").length >= 1);
});

// WHY: env vars without secret-like keys are safe.
test("cloud-aws-lambda-env-secrets: non-secret env vars are NOT flagged", () => {
  const code = `{ "Environment": { "Variables": { "LOG_LEVEL": "info", "REGION": "us-east-1" } } }`;
  assert.equal(findingsFor(code, "cloud-aws-lambda-env-secrets").length, 0);
});

// WHY: severity + owasp for Lambda env secrets.
test("cloud-aws-lambda-env-secrets: metadata is high + A05", () => {
  const r = ruleById("cloud-aws-lambda-env-secrets")!;
  assert.equal(r.severity, "high");
  assert.equal(r.owasp, "A05:2021 Security Misconfiguration");
});
