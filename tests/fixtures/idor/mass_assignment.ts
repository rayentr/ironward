// Profile update endpoint — mass assignment.
// Spreading req.body lets an attacker set any field, including
// role/credits/isAdmin that the UI never exposes.

import { prisma } from "./db";

export async function updateProfile(req: Request, res: Response) {
  const userId = req.user.id;

  // Bug: whole body trusted; attacker can send { role: "admin", credits: 9999 }
  const updated = await prisma.user.update({
    where: { id: userId },
    data: req.body,
  });

  res.json(updated);
}

export async function updateOrder(req: Request, res: Response) {
  const orderId = req.params.id;
  const existing = await db.orders.findById(orderId);

  // Object.assign of req.body — same mass-assignment issue.
  Object.assign(existing, req.body);
  await db.orders.save(existing);
  res.json(existing);
}
