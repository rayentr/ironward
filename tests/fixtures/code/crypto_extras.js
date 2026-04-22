// Extra crypto rules: ECB, hardcoded IV, RSA padding, short RSA, short AES, bcrypt rounds, scrypt N.

const crypto = require("crypto");

// crypto-hardcoded-iv
const c1 = crypto.createCipheriv("aes-256-gcm", key, Buffer.from("00112233445566778899aabbccddeeff"));
const c2 = crypto.createCipheriv("aes-256-cbc", key, "0123456789ABCDEF");

// crypto-ecb-mode
const c3 = crypto.createCipheriv("aes-128-ecb", key, null);
const c4 = crypto.createCipher("des-ecb", key);

// crypto-rsa-without-oaep
const enc = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, msg);

// crypto-short-rsa-key
crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
crypto.generateKeyPair("rsa", { modulusLength: 512, publicKeyEncoding: {} });

// crypto-short-aes-key
const c5 = crypto.createCipheriv("aes-64-cbc", key, iv);
const c6 = crypto.createCipheriv("aes-40-cbc", key, iv);

// bcrypt-short-salt-rounds
bcrypt.hash("pw", 4);
bcrypt.hashSync("pw", 6);

// scrypt-low-n
crypto.scryptSync(pw, salt, 64, { N: 1024, r: 8, p: 1 });
