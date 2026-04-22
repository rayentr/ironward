// Node-specific extras.
const child_process = require("child_process");
const fs = require("fs");

// child-process-exec-template
child_process.exec(`git log ${req.body.branch}`, cb);

// require-user-input
const mod = require(req.body.modName);

// fs-write-user-path
fs.writeFile(req.body.path, "data", cb);
fs.appendFileSync(req.params.file, "extra");
