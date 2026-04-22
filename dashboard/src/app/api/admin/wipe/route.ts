import { NextResponse } from "next/server";
import { wipe } from "@/lib/db";

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as { demoOnly?: boolean };
  const result = wipe({ demoOnly: body.demoOnly === true });
  return NextResponse.json({ ok: true, ...result });
}
