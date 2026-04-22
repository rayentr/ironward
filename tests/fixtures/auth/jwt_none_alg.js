// Custom JWT verifier that trusts the alg header from the token itself
// and accepts `alg: none`, skipping signature verification entirely.

const crypto = require("crypto");

function verifyToken(token, secret) {
  const [headerB64, payloadB64, sig] = token.split(".");
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());

  if (header.alg === "none") {
    // Bug: attacker forges a token with alg=none and no signature; we accept it.
    return payload;
  }

  const expected = crypto
    .createHmac(header.alg.toLowerCase().replace("hs", "sha"), secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest("base64url");

  if (expected !== sig) throw new Error("bad signature");
  // Missing: no `exp` / `nbf` / `iss` / `aud` checks.
  return payload;
}

module.exports = { verifyToken };
