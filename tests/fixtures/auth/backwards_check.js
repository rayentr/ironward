// Express admin endpoint — backwards auth check.
// The guard reads `if (user)` when it should be `if (!user)` (or equivalent),
// so requests WITHOUT a session reach the admin handler.

app.post("/admin/users/:id/promote", async (req, res) => {
  const user = req.session?.user;
  if (user) {
    // Bug: allow-list branch is actually the unauthenticated path.
    await db.users.update({ id: req.params.id }, { role: "admin" });
    return res.json({ ok: true });
  }
  // Authenticated users hit this and are rejected.
  return res.status(401).json({ error: "unauthorized" });
});
