// Weak crypto + Math.random used for tokens.

const crypto = require("crypto");

function hash(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function legacyHash(data) {
  return crypto.createHash("sha1").update(data).digest("hex");
}

function resetToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}

function sessionId() {
  const id = Date.now().toString() + Math.random();
  return id;
}

function encrypt(plaintext, key) {
  const cipher = crypto.createCipheriv("des-ede3-cbc", key, iv);
  return cipher.update(plaintext, "utf8", "hex") + cipher.final("hex");
}
