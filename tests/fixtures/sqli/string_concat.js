// Node/Express login handler — classic string-concat SQLi.

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const q = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
  const rows = await db.query(q);
  if (rows.length > 0) {
    req.session.user = rows[0];
    return res.json({ ok: true });
  }
  res.status(401).json({ ok: false });
});
