// Express search endpoint — reflected XSS via response interpolation.

app.get("/search", (req, res) => {
  res.send(`<html><body><h1>Results for: ${req.query.q}</h1></body></html>`);
});
