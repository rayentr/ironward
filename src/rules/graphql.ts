import type { CodeRule } from "../engines/code-rules.js";

export const GRAPHQL_RULES: CodeRule[] = [
  {
    id: "graphql-introspection-prod",
    severity: "medium",
    category: "framework" as any,
    confidence: 80,
    owasp: "A05:2021 Security Misconfiguration",
    languages: ["javascript", "typescript"],
    title: "GraphQL server initialized with introspection: true",
    // Match Apollo / yoga init objects that explicitly enable introspection.
    re: /\b(?:new\s+ApolloServer|createYoga|createSchema|ApolloServer)\s*\([\s\S]{0,400}?\bintrospection\s*:\s*true\b/g,
    rationale: "Introspection lets any caller download the full schema, including hidden mutations and admin types — a major recon win for attackers in production.",
    fix: "Set `introspection: process.env.NODE_ENV !== 'production'` (or `false` outright). Gate the GraphQL playground the same way.",
  },
  {
    id: "graphql-no-depth-limit",
    severity: "high",
    category: "framework" as any,
    confidence: 60,
    owasp: "A04:2021 Insecure Design",
    languages: ["javascript", "typescript"],
    title: "Apollo / yoga server with no depthLimit / maxDepth plugin",
    // Init call whose options block lacks any depth-limiting plugin.
    re: /\b(?:new\s+ApolloServer|createYoga)\s*\(\s*\{[\s\S]{0,500}?\}\s*\)/g,
    rationale: "Without a depth limit, a single request like `{ a { a { a { ... } } } }` can recurse arbitrarily and DoS the resolver layer.",
    fix: "Add `graphql-depth-limit` (Apollo) or `useDepthLimit` (yoga / envelop) capped at ~7-10 levels.",
    negativePattern: /\b(?:depthLimit|maxDepth|useDepthLimit|depth-limit)\b/,
  },
  {
    id: "graphql-resolver-no-auth",
    severity: "high",
    category: "framework" as any,
    confidence: 55,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "GraphQL resolver reads sensitive entities without checking context.user",
    // Resolver-shaped arrow that touches a db.users / users / accounts call.
    re: /\(\s*(?:parent|_+|root)\s*,\s*\w+\s*,\s*context\s*\)\s*=>\s*\{[\s\S]{0,300}?\b(?:db|prisma|knex|models?)\s*\.\s*(?:users?|accounts?|payments?|invoices?|orders?)\b[\s\S]{0,200}?\}/g,
    rationale: "Resolvers run with the caller's GraphQL context. Touching user / account tables without checking `context.user` / `context.auth` is broken access control.",
    fix: "Guard the resolver with `if (!context.user) throw new GraphQLError('UNAUTHENTICATED')` and scope the query by the caller's id.",
    negativePattern: /\bcontext\s*\.\s*(?:user|auth|session|userId|isAuthenticated)\b/,
  },
  {
    id: "graphql-mutation-no-auth",
    severity: "high",
    category: "framework" as any,
    confidence: 60,
    owasp: "A01:2021 Broken Access Control",
    languages: ["javascript", "typescript"],
    title: "Mutation resolver field with no context.user / auth check in body",
    // A mutation field declaration whose resolver body lacks any auth check.
    re: /\bMutation\s*:\s*\{[\s\S]{0,400}?\b\w+\s*:\s*(?:async\s*)?\(\s*\w+\s*,\s*\w+\s*,\s*context\s*\)\s*=>\s*\{[\s\S]{0,400}?\}/g,
    rationale: "Mutations change state. An unauthenticated mutation lets anyone with the endpoint URL create / edit / delete data on behalf of any user.",
    fix: "Use a `requireAuth(context)` helper at the top of every mutation resolver, or wrap the mutations with a directive / middleware (e.g. `graphql-shield`).",
    negativePattern: /\bcontext\s*\.\s*(?:user|auth|session|userId|isAuthenticated)|\brequireAuth\b|\bensureAuth\b/,
  },
  {
    id: "graphql-no-query-complexity",
    severity: "medium",
    category: "framework" as any,
    confidence: 55,
    owasp: "A04:2021 Insecure Design",
    languages: ["javascript", "typescript"],
    title: "GraphQL server init with no costAnalysis / complexity plugin",
    // Init block with no cost-analysis configuration.
    re: /\b(?:new\s+ApolloServer|createYoga)\s*\(\s*\{[\s\S]{0,500}?\}\s*\)/g,
    rationale: "Even a depth-limited query can pull millions of rows via wide selection sets. A complexity / cost analyzer rejects expensive queries before execution.",
    fix: "Plug in `graphql-cost-analysis`, `graphql-query-complexity`, or `useCostLimit` (envelop) with a reasonable per-request cap.",
    negativePattern: /\b(?:costAnalysis|queryComplexity|maxComplexity|complexity|useCostLimit|graphql-cost-analysis)\b/,
  },
  {
    id: "graphql-batching-no-limit",
    severity: "medium",
    category: "framework" as any,
    confidence: 55,
    owasp: "A04:2021 Insecure Design",
    languages: ["javascript", "typescript"],
    title: "GraphQL batch executor receives an array with no per-batch cap",
    // An executeBatch / batch executor over an array, without a length-limit nearby.
    // Capture ~120 chars of leading context so the negativePattern can spot a length cap.
    re: /[\s\S]{0,120}\b(?:executeBatch|graphqlBatch|batchExec|processBatch)\s*\(\s*(?:operations|queries|requests|batch|ops)\b/g,
    rationale: "Unbounded batching lets a single HTTP request smuggle hundreds of expensive operations, multiplying cost and bypassing per-request rate limits.",
    fix: "Cap batch size (e.g. `if (operations.length > 10) throw ...`) or disable batching unless your transport meters at the operation level.",
    negativePattern: /\.length\s*[<>=]|\bmaxBatch\b|\bbatchLimit\b|\bslice\s*\(\s*0\s*,/,
  },
];
