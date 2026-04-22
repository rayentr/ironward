// Clean fixture — should produce zero findings.
import process from "node:process";

const config = {
  awsKey: process.env.AWS_ACCESS_KEY_ID,
  stripeLive: process.env.STRIPE_SECRET_KEY,
  database: process.env.DATABASE_URL,
};

export default config;
