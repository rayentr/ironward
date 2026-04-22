// Express router — middleware is registered AFTER the sensitive route.
// The admin handler runs before requireAuth has a chance to reject.

import express from "express";
const router = express.Router();

router.get("/admin/reports", async (req, res) => {
  const reports = await db.reports.listAll();
  res.json(reports);
});

function requireAuth(req: any, res: any, next: any) {
  if (!req.session?.user) return res.status(401).end();
  next();
}

// Bug: registered too late — applies only to routes declared after this line.
router.use(requireAuth);

router.get("/admin/users", async (req, res) => {
  res.json(await db.users.listAll());
});
