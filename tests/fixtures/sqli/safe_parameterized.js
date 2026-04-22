// Correctly parameterized — pre-filter should not flag.

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const rows = await db.query(
    "SELECT * FROM users WHERE username = $1 AND password_hash = $2",
    [username, await hash(password)],
  );
  if (rows.length > 0) {
    req.session.user = rows[0];
    return res.json({ ok: true });
  }
  res.status(401).json({ ok: false });
});

async function listPosts(limit) {
  return db.query(
    "SELECT id, title FROM posts ORDER BY created_at DESC LIMIT $1",
    [limit],
  );
}
