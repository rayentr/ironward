// Admin endpoints without role checks — any authenticated user can hit them.

app.get("/admin/users", authRequired, async (req, res) => {
  // Only "authRequired" — no admin role check.
  const users = await db.users.findAll();
  res.json(users);
});

app.post("/admin/internal/promote", authRequired, async (req, res) => {
  // Role flag read straight from the request body — client can self-promote.
  if (req.body.isAdmin) {
    await db.users.update({ id: req.body.userId }, { role: "admin" });
  }
  res.json({ ok: true });
});

app.get("/debug/dump", async (req, res) => {
  res.json(await db.users.findAll({ include: ["password_hash", "api_keys"] }));
});
