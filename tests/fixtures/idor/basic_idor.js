// Invoice endpoint — classic IDOR.
// Any authenticated user can GET /api/invoice/:id and read any invoice
// just by guessing/incrementing the ID.

app.get("/api/invoice/:id", authRequired, async (req, res) => {
  const invoice = await db.invoice.findById(parseInt(req.params.id, 10));
  if (!invoice) return res.status(404).end();
  // Missing: no check that invoice.userId === req.user.id.
  res.json(invoice);
});

app.delete("/api/invoice/:id", authRequired, async (req, res) => {
  await db.invoice.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});
