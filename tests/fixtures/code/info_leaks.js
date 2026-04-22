// Info leaks: sourcemap comment, stack trace in response.

// source-map-reference-in-prod
//# sourceMappingURL=bundle.min.js.map

// stack-trace-in-response
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});

app.use((err, req, res, next) => {
  res.json({ error: err.stack });
});
