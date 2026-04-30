import { test } from "node:test";
import assert from "node:assert/strict";
import { scanText, type Finding } from "../../src/engines/secret-engine.ts";

async function findFor(code: string, type: string): Promise<Finding | undefined> {
  const found = await scanText(code, "test.ts");
  return found.find((f) => f.type === type);
}

const PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDExampleBody";
const PGP_BODY = "lQVYBE3Hg5sBDADs0jqXXn/MIIEvQIBADANBgkqExamplePgpBody";

// ============================================================
// private_key_pem (RSA / EC / DSA / OPENSSH / generic)
// ============================================================

// WHY: -----BEGIN RSA PRIVATE KEY----- is the canonical leak shape.
test("private_key_pem: RSA basic detection", async () => {
  const f = await findFor(`const k = "-----BEGIN RSA PRIVATE KEY-----\\n${PEM_BODY}\\n-----END RSA PRIVATE KEY-----";`, "private_key_pem");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: EC private keys are used for ECDSA — same severity, same shape.
test("private_key_pem: EC basic detection", async () => {
  const f = await findFor(`const k = "-----BEGIN EC PRIVATE KEY-----";`, "private_key_pem");
  assert.ok(f);
});

// WHY: generic PRIVATE KEY (PKCS#8) covers wrapped RSA/EC alike.
test("private_key_pem: generic PRIVATE KEY", async () => {
  const f = await findFor(`const k = "-----BEGIN PRIVATE KEY-----\\n${PEM_BODY}\\n-----END PRIVATE KEY-----";`, "private_key_pem");
  assert.ok(f);
});

// WHY: DSA private keys are still found in legacy systems.
test("private_key_pem: DSA basic detection", async () => {
  const f = await findFor(`const k = "-----BEGIN DSA PRIVATE KEY-----";`, "private_key_pem");
  assert.ok(f);
});

// WHY: env reference safe.
test("private_key_pem: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.RSA_PRIVATE_KEY;`, "private_key_pem");
  assert.equal(f, undefined);
});

// ============================================================
// pgp_private_key
// ============================================================

// WHY: PGP private key block is the canonical leak shape.
test("pgp_private_key: basic detection", async () => {
  const f = await findFor(`const k = "-----BEGIN PGP PRIVATE KEY BLOCK-----\\n${PGP_BODY}\\n-----END PGP PRIVATE KEY BLOCK-----";`, "pgp_private_key");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: header alone (no body) still indicates a key was committed.
test("pgp_private_key: header alone fires", async () => {
  const f = await findFor(`-----BEGIN PGP PRIVATE KEY BLOCK-----`, "pgp_private_key");
  assert.ok(f);
});

// WHY: header in object property.
test("pgp_private_key: object property", async () => {
  const f = await findFor(`const cfg = { gpg: "-----BEGIN PGP PRIVATE KEY BLOCK-----" };`, "pgp_private_key");
  assert.ok(f);
});

// WHY: header in template literal (multiline cert build).
test("pgp_private_key: template literal", async () => {
  const f = await findFor("const k = `-----BEGIN PGP PRIVATE KEY BLOCK-----`;", "pgp_private_key");
  assert.ok(f);
});

// WHY: env reference safe (path to keyring file).
test("pgp_private_key: env reference NOT flagged", async () => {
  const f = await findFor(`const path = process.env.GPG_KEY_PATH;`, "pgp_private_key");
  assert.equal(f, undefined);
});

// ============================================================
// ssh_dsa_private
// ============================================================

// WHY: -----BEGIN DSA PRIVATE KEY----- specifically targets legacy SSH DSA.
test("ssh_dsa_private: basic detection", async () => {
  const f = await findFor(`const k = "-----BEGIN DSA PRIVATE KEY-----";`, "ssh_dsa_private");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: header alone is enough — body might be elsewhere.
test("ssh_dsa_private: header alone fires", async () => {
  const f = await findFor(`-----BEGIN DSA PRIVATE KEY-----`, "ssh_dsa_private");
  assert.ok(f);
});

// WHY: header nested in config.
test("ssh_dsa_private: object property", async () => {
  const f = await findFor(`const cfg = { ssh: "-----BEGIN DSA PRIVATE KEY-----" };`, "ssh_dsa_private");
  assert.ok(f);
});

// WHY: header in template literal.
test("ssh_dsa_private: template literal", async () => {
  const f = await findFor("const k = `-----BEGIN DSA PRIVATE KEY-----`;", "ssh_dsa_private");
  assert.ok(f);
});

// WHY: env reference safe.
test("ssh_dsa_private: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.SSH_DSA_KEY;`, "ssh_dsa_private");
  assert.equal(f, undefined);
});

// ============================================================
// ssh_openssh_private
// ============================================================

// WHY: -----BEGIN OPENSSH PRIVATE KEY----- is modern ssh-keygen default.
test("ssh_openssh_private: basic detection", async () => {
  const f = await findFor(`const k = "-----BEGIN OPENSSH PRIVATE KEY-----";`, "ssh_openssh_private");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: header alone fires.
test("ssh_openssh_private: header alone fires", async () => {
  const f = await findFor(`-----BEGIN OPENSSH PRIVATE KEY-----`, "ssh_openssh_private");
  assert.ok(f);
});

// WHY: header in object property.
test("ssh_openssh_private: object property", async () => {
  const f = await findFor(`const cfg = { deploy: "-----BEGIN OPENSSH PRIVATE KEY-----" };`, "ssh_openssh_private");
  assert.ok(f);
});

// WHY: header in template literal.
test("ssh_openssh_private: template literal", async () => {
  const f = await findFor("const k = `-----BEGIN OPENSSH PRIVATE KEY-----`;", "ssh_openssh_private");
  assert.ok(f);
});

// WHY: env reference safe.
test("ssh_openssh_private: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.SSH_PRIVATE_KEY;`, "ssh_openssh_private");
  assert.equal(f, undefined);
});

// ============================================================
// ssh_encrypted_private
// ============================================================

// WHY: -----BEGIN ENCRYPTED PRIVATE KEY----- needs separate detection — the
// passphrase may also be exposed nearby.
test("ssh_encrypted_private: basic detection", async () => {
  const f = await findFor(`const k = "-----BEGIN ENCRYPTED PRIVATE KEY-----";`, "ssh_encrypted_private");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: header alone fires.
test("ssh_encrypted_private: header alone fires", async () => {
  const f = await findFor(`-----BEGIN ENCRYPTED PRIVATE KEY-----`, "ssh_encrypted_private");
  assert.ok(f);
});

// WHY: header in object property.
test("ssh_encrypted_private: object property", async () => {
  const f = await findFor(`const cfg = { key: "-----BEGIN ENCRYPTED PRIVATE KEY-----" };`, "ssh_encrypted_private");
  assert.ok(f);
});

// WHY: header in template literal.
test("ssh_encrypted_private: template literal", async () => {
  const f = await findFor("const k = `-----BEGIN ENCRYPTED PRIVATE KEY-----`;", "ssh_encrypted_private");
  assert.ok(f);
});

// WHY: env reference safe.
test("ssh_encrypted_private: env reference NOT flagged", async () => {
  const f = await findFor(`const k = process.env.ENCRYPTED_KEY;`, "ssh_encrypted_private");
  assert.equal(f, undefined);
});

// ============================================================
// putty_ppk_private
// ============================================================

// WHY: PuTTY .ppk format is widely used on Windows; canonical detection.
test("putty_ppk_private: rsa basic detection", async () => {
  const f = await findFor(`PuTTY-User-Key-File-3: ssh-rsa`, "putty_ppk_private");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

// WHY: ed25519 PPK is also used.
test("putty_ppk_private: ed25519 detection", async () => {
  const f = await findFor(`PuTTY-User-Key-File-2: ssh-ed25519`, "putty_ppk_private");
  assert.ok(f);
});

// WHY: ecdsa PPK detection.
test("putty_ppk_private: ecdsa detection", async () => {
  const f = await findFor(`PuTTY-User-Key-File-3: ssh-ecdsa`, "putty_ppk_private");
  assert.ok(f);
});

// WHY: dss/dsa PPK detection.
test("putty_ppk_private: dss detection", async () => {
  const f = await findFor(`PuTTY-User-Key-File-2: ssh-dss`, "putty_ppk_private");
  assert.ok(f);
});

// WHY: env reference safe.
test("putty_ppk_private: env reference NOT flagged", async () => {
  const f = await findFor(`const path = process.env.PPK_PATH;`, "putty_ppk_private");
  assert.equal(f, undefined);
});
