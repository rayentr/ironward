// Correctly-guarded endpoint — tests should produce zero auth findings.

import express from "express";
const router = express.Router();

function requireAuth(req: any, res: any, next: any) {
  if (!req.session?.user) return res.status(401).end();
  next();
}

router.use(requireAuth);

router.patch("/orders/:id", async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  if (!order) return res.status(404).end();
  if (order.customerId !== req.session.user.id) return res.status(403).end();

  order.shippingAddress = req.body.shippingAddress;
  await db.orders.save(order);
  res.json(order);
});

export default router;
