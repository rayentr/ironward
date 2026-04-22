// Intentionally vulnerable test fixture for SecureMCP.
// DO NOT copy these values anywhere. They are fake format-matching strings.

const config = {
  awsKey: "AKIAZ7YXGPDXJ5T2QLMN",
  stripeLive: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
  githubToken: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
  database: "postgres://admin:Pr0d@dm1n@db.internal:5432/app",
};

// Should be caught by entropy analysis: no prefix, but high H
const mysterySecret = "Zx9pQ7Rv2LmK4Nt8Wj3Hb6Fy1Cd5Ae0G";

// Generic password assignment
const password = "Pr0d@dm1n#2024!";

module.exports = config;
