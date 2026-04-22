import { test } from "node:test";
import assert from "node:assert/strict";
import { scanInfraFile, runScanInfra, detectInfraKind } from "../src/tools/scan-infra.ts";

function ids(findings: ReturnType<typeof scanInfraFile>) {
  return new Set(findings.map((f) => f.ruleId));
}

test("detectInfraKind recognizes .tf as terraform", () => {
  assert.equal(detectInfraKind("main.tf", 'resource "aws_s3_bucket" "b" {}'), "terraform");
  assert.equal(detectInfraKind("main.tf.json", "{}"), "terraform");
});

test("detectInfraKind recognizes CFN by AWSTemplateFormatVersion", () => {
  assert.equal(
    detectInfraKind("stack.yml", "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Foo:\n    Type: AWS::S3::Bucket"),
    "cloudformation",
  );
});

test("detectInfraKind returns null for non-IaC", () => {
  assert.equal(detectInfraKind("foo.md", "hello"), null);
  assert.equal(detectInfraKind("compose.yml", "services:\n  web:\n"), null);
});

test("S3 public-read ACL fires tf-s3-bucket-public-read", () => {
  const tf = `
resource "aws_s3_bucket_acl" "b" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}`;
  assert.ok(ids(scanInfraFile(tf, "terraform")).has("tf-s3-bucket-public-read"));
});

test("security group 0.0.0.0/0 on SSH fires tf-sg-ingress-0-0-0-0-ssh", () => {
  const tf = `
resource "aws_security_group" "s" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`;
  assert.ok(ids(scanInfraFile(tf, "terraform")).has("tf-sg-ingress-0-0-0-0-ssh"));
});

test("RDS publicly_accessible = true fires", () => {
  const tf = `
resource "aws_db_instance" "db" {
  publicly_accessible = true
}`;
  assert.ok(ids(scanInfraFile(tf, "terraform")).has("tf-rds-publicly-accessible"));
});

test("unencrypted EBS fires tf-unencrypted-ebs", () => {
  const tf = `
resource "aws_ebs_volume" "v" {
  encrypted = false
  size      = 20
}`;
  assert.ok(ids(scanInfraFile(tf, "terraform")).has("tf-unencrypted-ebs"));
});

test("CFN public-read bucket fires cfn-s3-public-read", () => {
  const cfn = `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead`;
  assert.ok(ids(scanInfraFile(cfn, "cloudformation")).has("cfn-s3-public-read"));
});

test("runScanInfra aggregates and produces summary", async () => {
  const tf = `
resource "aws_db_instance" "db" {
  publicly_accessible = true
}
resource "aws_ebs_volume" "v" {
  encrypted = false
}`;
  const out = await runScanInfra({ files: [{ path: "main.tf", content: tf }] });
  assert.equal(out.files.length, 1);
  assert.ok(out.summary.totalFindings >= 2);
});

test("runScanInfra ignores non-IaC files", async () => {
  const out = await runScanInfra({
    files: [{ path: "README.md", content: "hello" }],
  });
  assert.equal(out.files.length, 0);
});
