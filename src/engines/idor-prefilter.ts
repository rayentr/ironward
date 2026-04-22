export interface IdorSuspect {
  line: number;
  snippet: string;
  reason: string;
}

const FETCH_METHOD =
  "(?:findById|findByPk|findOne|findUnique|findFirst|getById|retrieve|fetchById|findByIdAndDelete|findByIdAndUpdate|findOneAndUpdate|findOneAndDelete)";

const REQUEST_ACCESS =
  "(?:req|request|ctx|event|_req|args)\\.(?:params|body|query|headers)";

const ORM_FETCH_WITH_ID =
  `\\.${FETCH_METHOD}\\s*\\((?=[\\s\\S]{0,200}?${REQUEST_ACCESS})`;

const RULES: Array<{ name: string; re: RegExp; reason: string }> = [
  {
    name: "orm_fetch_by_request_id",
    re: new RegExp(ORM_FETCH_WITH_ID, "g"),
    reason: "Resource fetched by ID from request — ownership check may be missing",
  },
  {
    name: "sql_select_by_request_id",
    re: new RegExp(
      `\\b(?:query|execute|sql|raw)\\s*\\(\\s*["'\\\`][^"'\\\`\\n]*\\bWHERE\\b\\s+id\\s*=\\s*[?$][0-9]?[^"'\\\`\\n]*["'\\\`]\\s*,\\s*\\[?\\s*(?:req|request|ctx|params|body|event)\\.`,
      "gi",
    ),
    reason: "SQL SELECT by ID bound directly from request — check ownership in WHERE",
  },
  {
    name: "mass_assignment_update",
    re: /\.(?:update|updateOne|findByIdAndUpdate|findOneAndUpdate|updateMany|merge|save)\s*\(\s*\{\s*(?:id\s*:\s*(?:req|request|params|body)\.[^,}]+\s*,)?\s*\.{3}(?:req|request|ctx|params|body|event)\.body/g,
    reason: "Mass-assignment: whole req.body spread into update — unsafe fields can be overwritten",
  },
  {
    name: "mass_assignment_object_assign",
    re: /Object\.assign\s*\(\s*[A-Za-z_$][\w.]*\s*,\s*(?:req|request|ctx|params|body|event)\.body/g,
    reason: "Object.assign of req.body into a model — mass assignment",
  },
  {
    name: "prisma_update_spread_body",
    re: /prisma\.[A-Za-z_$][\w]*\s*\.(?:update|upsert|create|updateMany)\s*\((?=[\s\S]{0,300}?data\s*:\s*(?:req|request|ctx|body|event)\.body\b)/g,
    reason: "Prisma write with data: req.body — mass assignment risk",
  },
  {
    name: "express_admin_route_no_role",
    re: /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["'`]\/[^"'`]*\b(?:admin|internal|debug|_admin)\b[^"'`]*["'`]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>/g,
    reason: "Admin-looking route declared without a middleware — verify role check exists",
  },
  {
    name: "django_queryset_get_by_id",
    re: /\.objects\.(?:get|filter)\s*\(\s*(?:id|pk)\s*=\s*(?:request|self\.request|view\.request|params)\./g,
    reason: "Django .objects.get()/filter() keyed only by request ID — add owner filter",
  },
  {
    name: "flask_model_query_get",
    re: /\.query\s*\.\s*get(?:_or_404)?\s*\(\s*(?:request\.args|request\.json|request\.form|request\.view_args|params)\./g,
    reason: "Flask Model.query.get() by request-provided ID — verify current_user owns resource",
  },
  {
    name: "sequential_integer_id_cast",
    re: /parseInt\s*\(\s*(?:req|request|ctx|params|event)\.(?:params|query|body)\.[A-Za-z_$][\w]*\s*(?:,\s*10)?\s*\)/g,
    reason: "Parsing request ID as integer — sequential IDs enable easy enumeration; prefer UUIDs",
  },
  {
    name: "next_api_handler_no_auth",
    re: /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\(\s*(?:req|request|_req)/g,
    reason: "Next.js App Router route handler — confirm session / ownership check is present",
  },
  {
    name: "role_check_from_user_input",
    re: /\bif\s*\(\s*(?:req|request|ctx|body|params|event)\.(?:body|query|params|headers)\.(?:role|isAdmin|is_admin|admin)\b/g,
    reason: "Role flag read from user input — authorization based on client-supplied data",
  },
  {
    name: "raw_find_no_where_owner",
    re: /\b(?:db|knex|Model)\.raw\s*\(\s*["'`][^"'`]*\bFROM\b[^"'`]*\bWHERE\b\s+id\s*=/gi,
    reason: "Raw SELECT FROM … WHERE id = … — ensure owner_id is also in the WHERE clause",
  },
];

function lineFromIndex(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function truncate(s: string, n = 180): string {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

// Signals that an ownership check LIKELY exists in the file — still worth flagging,
// but Opus will be told to weigh this.
export const OWNERSHIP_HINTS = [
  /\buserId\s*:\s*(?:req|request|ctx|session|current_user|currentUser)\.user\.id\b/,
  /\bowner(?:Id)?\s*:\s*(?:req|request|ctx|session|current_user|currentUser)\.user\.id\b/,
  /\b(?:current_user|currentUser|req\.user|request\.user)\.id\b\s*===?\s*[A-Za-z_$][\w.]*/,
  /\.filter_by\s*\([^)]*user_id\s*=\s*current_user\.id/,
  /\b@login_required\b|\bensureAuthenticated\b|\bisAuthenticated\(\)/,
];

export function findIdorSuspects(code: string): IdorSuspect[] {
  const suspects: IdorSuspect[] = [];
  const seen = new Set<string>();
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.re.exec(code)) !== null) {
      const line = lineFromIndex(code, m.index);
      const key = `${line}:${rule.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      suspects.push({
        line,
        snippet: truncate(m[0].replace(/\s+/g, " ").trim()),
        reason: rule.reason,
      });
    }
  }
  suspects.sort((a, b) => a.line - b.line);
  return suspects;
}

export function ownershipHintCount(code: string): number {
  let count = 0;
  for (const re of OWNERSHIP_HINTS) if (re.test(code)) count++;
  return count;
}
