export interface SqlSuspect {
  line: number;
  snippet: string;
  reason: string;
}

const SQL_VERB =
  "(?:SELECT|INSERT\\s+INTO|UPDATE|DELETE\\s+FROM|REPLACE\\s+INTO|MERGE|CALL|EXEC(?:UTE)?|TRUNCATE|ALTER\\s+TABLE|DROP\\s+TABLE|CREATE\\s+TABLE)";

const DQ = `"[^"\\n]*\\b${SQL_VERB}\\b[^"\\n]*"`;
const SQ = `'[^'\\n]*\\b${SQL_VERB}\\b[^'\\n]*'`;
const BT = "`[^`\\n]*\\b" + SQL_VERB + "\\b[^`\\n]*`";
const ID = "[A-Za-z_$][A-Za-z0-9_$.\\[\\]]*";

const RULES: Array<{ name: string; re: RegExp; reason: string }> = [
  {
    name: "js_string_concat_with_sql_dq",
    re: new RegExp(`${DQ}\\s*\\+\\s*${ID}`, "gi"),
    reason: "SQL string concatenated with a non-literal",
  },
  {
    name: "js_string_concat_with_sql_sq",
    re: new RegExp(`${SQ}\\s*\\+\\s*${ID}`, "gi"),
    reason: "SQL string concatenated with a non-literal",
  },
  {
    name: "js_string_concat_reverse_dq",
    re: new RegExp(`${ID}\\s*\\+\\s*${DQ}`, "gi"),
    reason: "SQL string concatenated with a non-literal (reversed)",
  },
  {
    name: "js_string_concat_reverse_sq",
    re: new RegExp(`${ID}\\s*\\+\\s*${SQ}`, "gi"),
    reason: "SQL string concatenated with a non-literal (reversed)",
  },
  {
    name: "template_literal_with_sql",
    re: new RegExp("`[^`]*\\b" + SQL_VERB + "\\b[^`]*\\$\\{[^}]+\\}[^`]*`", "gi"),
    reason: "Template literal with interpolated SQL",
  },
  {
    name: "python_fstring_with_sql_dq",
    re: new RegExp(
      `(?:f|rf|fr|F|RF|FR)"[^"\\n]*\\b${SQL_VERB}\\b[^"\\n]*\\{[^}\\n]+\\}[^"\\n]*"`,
      "gi",
    ),
    reason: "Python f-string composing a SQL statement",
  },
  {
    name: "python_fstring_with_sql_sq",
    re: new RegExp(
      `(?:f|rf|fr|F|RF|FR)'[^'\\n]*\\b${SQL_VERB}\\b[^'\\n]*\\{[^}\\n]+\\}[^'\\n]*'`,
      "gi",
    ),
    reason: "Python f-string composing a SQL statement",
  },
  {
    name: "python_percent_format_dq",
    re: new RegExp(`"[^"\\n]*\\b${SQL_VERB}\\b[^"\\n]*%[sd][^"\\n]*"\\s*%\\s*`, "gi"),
    reason: "SQL built with %-formatting of non-literal input",
  },
  {
    name: "python_percent_format_sq",
    re: new RegExp(`'[^'\\n]*\\b${SQL_VERB}\\b[^'\\n]*%[sd][^'\\n]*'\\s*%\\s*`, "gi"),
    reason: "SQL built with %-formatting of non-literal input",
  },
  {
    name: "python_str_format_dq",
    re: new RegExp(
      `"[^"\\n]*\\b${SQL_VERB}\\b[^"\\n]*\\{[^}\\n]*\\}[^"\\n]*"\\s*\\.\\s*format\\s*\\(`,
      "gi",
    ),
    reason: "SQL built with str.format() of non-literal input",
  },
  {
    name: "python_str_format_sq",
    re: new RegExp(
      `'[^'\\n]*\\b${SQL_VERB}\\b[^'\\n]*\\{[^}\\n]*\\}[^'\\n]*'\\s*\\.\\s*format\\s*\\(`,
      "gi",
    ),
    reason: "SQL built with str.format() of non-literal input",
  },
  {
    name: "orm_raw_with_interpolation",
    re: /\b(?:raw|query\.raw|queryRaw|\$queryRaw(?:Unsafe)?|executeRaw|\$executeRaw(?:Unsafe)?|unsafeRaw)\s*(?:<[^>]+>\s*)?\(\s*[`"'][^`"']*\$\{[^}]+\}/gi,
    reason: "ORM raw() call with an interpolated argument",
  },
  {
    name: "sequelize_query_concat",
    re: /\bsequelize\.query\s*\(\s*["'`][^"'`\n]+["'`]\s*\+\s*[A-Za-z_$]/gi,
    reason: "sequelize.query() built via string concatenation",
  },
  {
    name: "knex_raw_interpolation",
    re: /\bknex\.raw\s*\(\s*`[^`]*\$\{[^}]+\}/gi,
    reason: "knex.raw() with an interpolated argument",
  },
  {
    name: "mysql_query_concat_dq",
    re: new RegExp(
      `\\b(?:connection|conn|db|pool|client)\\.query\\s*\\(\\s*${DQ}\\s*\\+`,
      "gi",
    ),
    reason: "DB client query() with string concatenation",
  },
  {
    name: "mysql_query_concat_sq",
    re: new RegExp(
      `\\b(?:connection|conn|db|pool|client)\\.query\\s*\\(\\s*${SQ}\\s*\\+`,
      "gi",
    ),
    reason: "DB client query() with string concatenation",
  },
  {
    name: "php_concat_sql_dq",
    re: new RegExp(`${DQ}\\s*\\.\\s*\\$[A-Za-z_][A-Za-z0-9_]*`, "gi"),
    reason: "PHP dot-concat of SQL string with variable",
  },
  {
    name: "php_concat_sql_sq",
    re: new RegExp(`${SQ}\\s*\\.\\s*\\$[A-Za-z_][A-Za-z0-9_]*`, "gi"),
    reason: "PHP dot-concat of SQL string with variable",
  },
  {
    name: "php_double_quoted_interpolation",
    re: new RegExp(`"[^"\\n]*\\b${SQL_VERB}\\b[^"\\n]*\\$\\{?[A-Za-z_][A-Za-z0-9_]*\\}?[^"\\n]*"`, "gi"),
    reason: "PHP double-quoted SQL string with variable interpolation",
  },
  {
    name: "go_sprintf_sql_dq",
    re: new RegExp(
      `fmt\\.Sprintf\\s*\\(\\s*"[^"\\n]*\\b${SQL_VERB}\\b[^"\\n]*%[svd][^"\\n]*"\\s*,`,
      "gi",
    ),
    reason: "Go fmt.Sprintf building a SQL statement",
  },
  {
    name: "go_sprintf_sql_bt",
    re: new RegExp(
      "fmt\\.Sprintf\\s*\\(\\s*`[^`\\n]*\\b" + SQL_VERB + "\\b[^`\\n]*%[svd][^`\\n]*`\\s*,",
      "gi",
    ),
    reason: "Go fmt.Sprintf building a SQL statement",
  },
  {
    name: "java_string_concat_sql_dq",
    re: new RegExp(`${DQ}\\s*\\+\\s*[A-Za-z_][A-Za-z0-9_.]*`, "gi"),
    reason: "Java/C#-style string concatenation building SQL",
  },
  {
    name: "ruby_string_interp_sql",
    re: new RegExp(`"[^"\\n]*\\b${SQL_VERB}\\b[^"\\n]*#\\{[^}\\n]+\\}[^"\\n]*"`, "gi"),
    reason: "Ruby string interpolation building SQL",
  },
  {
    name: "activerecord_where_interpolation",
    re: /\.where\s*\(\s*["'`][^"'`\n]*#\{[^}\n]+\}[^"'`\n]*["'`]/gi,
    reason: "ActiveRecord .where() with string interpolation",
  },
];

function lineFromIndex(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function truncate(s: string, n = 160): string {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

export function findSqlSuspects(code: string): SqlSuspect[] {
  const suspects: SqlSuspect[] = [];
  const seenLineReason = new Set<string>();
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.re.exec(code)) !== null) {
      const line = lineFromIndex(code, m.index);
      const key = `${line}:${rule.reason}`;
      if (seenLineReason.has(key)) continue;
      seenLineReason.add(key);
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
