import { wipe } from "../src/lib/db";

const demoOnly = process.argv.includes("--demo");
const result = wipe({ demoOnly });

if (demoOnly) {
  console.log(`Cleared ${result.scansDeleted} demo scan${result.scansDeleted === 1 ? "" : "s"} and ${result.findingsDeleted} finding${result.findingsDeleted === 1 ? "" : "s"}.`);
} else {
  console.log(`Cleared ALL ${result.scansDeleted} scan${result.scansDeleted === 1 ? "" : "s"} and ${result.findingsDeleted} finding${result.findingsDeleted === 1 ? "" : "s"}.`);
}
