// Prisma/Knex-style raw SQL with interpolation — SQLi.

import { prisma } from "./db";

export async function ordersForCustomer(customerId: string) {
  // $queryRaw with a template literal is safe only with tagged-template placeholders.
  // The ${customerId} here is raw interpolation — SQL injection.
  const rows = await prisma.$queryRawUnsafe(
    `SELECT id, total FROM orders WHERE customer_id = '${customerId}' ORDER BY created_at DESC`,
  );
  return rows;
}

export async function topProducts(category: string) {
  return knex.raw(`SELECT * FROM products WHERE category = '${category}' LIMIT 10`);
}
