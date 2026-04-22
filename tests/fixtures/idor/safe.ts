// Correctly-scoped access — zero findings expected.

import { prisma } from "./db";
import { z } from "zod";

const UpdateOrder = z.object({
  shippingAddress: z.string().max(256),
  notes: z.string().max(1024).optional(),
});

export async function getOrder(req: Request, res: Response) {
  // Ownership filter in the query: can't accidentally leak other users' orders.
  const order = await prisma.order.findFirst({
    where: { id: req.params.id, userId: req.user.id },
  });
  if (!order) return res.status(404).end();
  res.json(order);
}

export async function updateOrder(req: Request, res: Response) {
  // Strict body validation — only the fields we allow.
  const data = UpdateOrder.parse(req.body);

  // Ownership check baked into the update's where clause.
  const result = await prisma.order.updateMany({
    where: { id: req.params.id, userId: req.user.id },
    data,
  });
  if (result.count === 0) return res.status(404).end();
  res.json({ ok: true });
}
