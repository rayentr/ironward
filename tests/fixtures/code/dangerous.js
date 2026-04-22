// Eval, Function constructor, child_process with user input.

const { exec } = require("child_process");

app.get("/run/:cmd", (req, res) => {
  const result = eval(req.query.code);
  const f = new Function("x", "return " + req.body.formula);

  exec("convert " + req.params.cmd, (err, stdout) => {
    res.send(stdout);
  });

  return res.json({ result, f });
});
