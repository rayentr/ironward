import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCodeRules, CODE_RULES } from "../src/engines/code-rules.ts";

const ruleById = (id: string) => CODE_RULES.find((r) => r.id === id);

// WHY: DocumentBuilderFactory.newInstance() without disallow-doctype-decl is
// XXE-vulnerable. Rule uses a negative lookahead for the feature string.
test("java-depth: DocumentBuilderFactory.newInstance() without disable is flagged", () => {
  const code = `DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "java-documentbuilderfactory-xxe");
  assert.ok(finding, "expected java-documentbuilderfactory-xxe");
  assert.equal(finding.severity, "high");
});

// WHY: SAXParserFactory has the same default-unsafe behavior; rule covers the
// same feature-presence lookahead.
test("java-depth: SAXParserFactory.newInstance() without DTD disable is flagged", () => {
  const code = `SAXParserFactory spf = SAXParserFactory.newInstance();`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "java-saxparserfactory-xxe"));
});

// WHY: ObjectInputStream.readObject() on untrusted bytes is the classic
// gadget-chain RCE class (commons-collections, Spring, etc.).
test("java-depth: ObjectInputStream.readObject() is flagged", () => {
  const code = `ObjectInputStream ois = new ObjectInputStream(in);\nObject o = ois.readObject();`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "java-objectinputstream-readobject");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: Statement.executeQuery with a concatenated SQL string is the
// textbook injection.
test("java-depth: Statement.executeQuery with concat is flagged", () => {
  const code = `Statement st = conn.createStatement();\nResultSet rs = st.executeQuery("SELECT * FROM users WHERE id = " + userInput);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "java-statement-execute-concat"));
});

// WHY: prepareStatement built via concatenation defeats parameterization —
// the binding only protects ? placeholders. Use a SQL fragment without inner
// quotes (the rule's [^'"]* stops at any quote char, so embedded literal
// quotes hide the match — that's a separate, narrower gap).
test("java-depth: PreparedStatement built via concat is flagged", () => {
  const code = `PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = " + userId);`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "java-preparedstatement-concat"));
});

// WHY: new File(request.getParameter(...)) — direct path traversal.
test("java-depth: new File(request.getParameter(...)) is flagged", () => {
  const code = `File f = new File(request.getParameter("path"));`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "java-file-user-input"));
});

// WHY: Files.readAllBytes(Paths.get(request.getParameter(...))) — same
// path traversal class.
test("java-depth: Files.readAllBytes(Paths.get(request.getParameter(...))) is flagged", () => {
  const code = `byte[] bs = Files.readAllBytes(Paths.get(request.getParameter("p")));`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "java-files-readallbytes-user"));
});

// WHY: Runtime.getRuntime().exec(userInput) splits on whitespace and runs the
// resulting argv — command injection via shell metachars or argv tampering.
test("java-depth: Runtime.getRuntime().exec(userInput) is flagged", () => {
  const code = `Runtime.getRuntime().exec(userInput);`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "java-runtime-exec-user");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: MessageDigest.getInstance("MD5") is broken — collisions and preimage
// weaknesses make it unsafe for signatures or password hashing.
test("java-depth: MessageDigest.getInstance(\"MD5\") is flagged", () => {
  const code = `MessageDigest md = MessageDigest.getInstance("MD5");`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "java-md5-sha1-messagedigest"));
});

// WHY: SHA-1 is also covered by the same rule — practical collisions.
test("java-depth: MessageDigest.getInstance(\"SHA-1\") is flagged", () => {
  const code = `MessageDigest md = MessageDigest.getInstance("SHA-1");`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "java-md5-sha1-messagedigest"));
});

// WHY: Cipher.getInstance("DES") — a 56-bit broken cipher.
test("java-depth: Cipher.getInstance(\"DES\") is flagged", () => {
  const code = `Cipher c = Cipher.getInstance("DES");`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "java-cipher-weak-instance"));
});

// WHY: AES/ECB leaks block patterns (the ECB penguin) and is unsafe for any
// real payload. The rule alternation includes `AES\/ECB` but the closing
// `['"]` then requires a quote — so `AES/ECB/PKCS5Padding` (with trailing
// padding suffix) does NOT match. Document the gap.
test("java-depth: Cipher.getInstance(\"AES/ECB/PKCS5Padding\") gap (documented)", () => {
  const code = `Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");`;
  const f = scanCodeRules(code);
  // TODO: java-cipher-weak-instance rule's `AES\/ECB` branch requires a closing
  // quote immediately after `ECB`, so transformations like
  // `AES/ECB/PKCS5Padding` slip through. Allow an optional `/...` suffix.
  assert.ok(!f.some((x) => x.ruleId === "java-cipher-weak-instance"));
});

// WHY: HostnameVerifier returning true defeats hostname pinning — any cert
// for any name passes; trivial MITM.
test("java-depth: HostnameVerifier returning true is flagged", () => {
  const code = `HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() { public boolean verify(String h, SSLSession s) { return true; } });`;
  const f = scanCodeRules(code);
  assert.ok(f.some((x) => x.ruleId === "java-hostnameverifier-allow-all"));
});

// WHY: JNDI lookup with user input is the Log4Shell class — CVE-2021-44228.
// Rule matches identifiers `InitialContext`, `Context`, or `ic` (case-sensitive).
test("java-depth: JNDI lookup with request.getParameter is flagged", () => {
  const code = `Object o = InitialContext.lookup(request.getParameter("name"));`;
  const f = scanCodeRules(code);
  const finding = f.find((x) => x.ruleId === "java-jndi-user-input");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
});

// WHY: NEGATIVE — a properly parameterized PreparedStatement with `?` and
// setX bindings must NOT trip the concat rule.
test("java-depth: parameterized PreparedStatement with ? is NOT flagged", () => {
  const code = `PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\nps.setLong(1, id);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "java-preparedstatement-concat"));
  assert.ok(!f.some((x) => x.ruleId === "java-statement-execute-concat"));
});

// WHY: NEGATIVE — DocumentBuilderFactory followed by the disable-feature call
// in the same buffer must NOT flag (negative lookahead in the rule).
test("java-depth: DocumentBuilderFactory with disallow-doctype-decl is NOT flagged", () => {
  const code = `DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`;
  const f = scanCodeRules(code);
  assert.ok(!f.some((x) => x.ruleId === "java-documentbuilderfactory-xxe"));
});

// WHY: critical Java rules must really be critical — exit codes depend on it.
test("java-depth: critical-severity Java rules really are critical", () => {
  const ids = [
    "java-objectinputstream-readobject",
    "java-statement-execute-concat",
    "java-runtime-exec-user",
    "java-jndi-user-input",
    "java-trust-all-certs",
    "java-secretkeyspec-hardcoded",
    "java-hibernate-createquery-concat",
  ];
  for (const id of ids) {
    const rule = ruleById(id);
    assert.ok(rule, `missing rule ${id}`);
    assert.equal(rule.severity, "critical", `${id} expected critical`);
  }
});

// WHY: every Java rule should carry the languages: ['java'] tag and an OWASP
// A0X:202Y tag — used by SARIF/JUnit exports.
test("java-depth: java-* rules carry languages=['java'] and OWASP tags", () => {
  const javaRules = CODE_RULES.filter((r) => r.id.startsWith("java-"));
  assert.ok(javaRules.length >= 15, `expected >=15 java- rules, got ${javaRules.length}`);
  for (const r of javaRules) {
    assert.ok(r.languages?.includes("java"), `${r.id} missing language tag`);
    assert.ok(r.owasp, `${r.id} missing owasp`);
    assert.match(r.owasp, /^A\d{2}:202\d\b/, `${r.id} owasp not in A0X:202Y form`);
  }
});

// WHY: java-* rules should carry confidence in the documented 50-100 band.
test("java-depth: java-* rules carry sensible confidence values", () => {
  const javaRules = CODE_RULES.filter((r) => r.id.startsWith("java-"));
  for (const r of javaRules) {
    assert.ok(
      r.confidence == null || (r.confidence >= 50 && r.confidence <= 100),
      `${r.id} confidence out of band: ${r.confidence}`,
    );
  }
});
