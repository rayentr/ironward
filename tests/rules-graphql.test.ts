import { test } from "node:test";
import assert from "node:assert/strict";
import { GRAPHQL_RULES } from "../src/rules/graphql.ts";

function fire(code: string, ruleId: string): boolean {
  const rule = GRAPHQL_RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error("rule not found: " + ruleId);
  rule.re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = rule.re.exec(code)) !== null) {
    if (rule.negativePattern && rule.negativePattern.test(m[0])) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      continue;
    }
    return true;
  }
  return false;
}

// WHY: explicit introspection: true in production code is the canonical leak.
test("graphql-introspection-prod: ApolloServer with introspection: true is flagged", () => {
  const code = `const server = new ApolloServer({ typeDefs, resolvers, introspection: true });`;
  assert.equal(fire(code, "graphql-introspection-prod"), true);
});

// WHY: introspection: false (or env-gated) is the safe pattern; must not flag
// the literal `false`.
test("graphql-introspection-prod: introspection: false is NOT flagged", () => {
  const code = `const server = new ApolloServer({ typeDefs, resolvers, introspection: false });`;
  assert.equal(fire(code, "graphql-introspection-prod"), false);
});

// WHY: lock severity + owasp shape.
test("graphql-introspection-prod: metadata is well-formed", () => {
  const r = GRAPHQL_RULES.find((x) => x.id === "graphql-introspection-prod")!;
  assert.equal(r.severity, "medium");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: an Apollo init with no depth-limit reference at all should fire.
test("graphql-no-depth-limit: bare Apollo init is flagged", () => {
  const code = `const server = new ApolloServer({ typeDefs, resolvers, csrfPrevention: true });`;
  assert.equal(fire(code, "graphql-no-depth-limit"), true);
});

// WHY: an init that wires depthLimit must NOT flag (negativePattern).
test("graphql-no-depth-limit: init with depthLimit plugin is NOT flagged", () => {
  const code = `const server = new ApolloServer({ typeDefs, resolvers, validationRules: [depthLimit(7)] });`;
  assert.equal(fire(code, "graphql-no-depth-limit"), false);
});

test("graphql-no-depth-limit: metadata is well-formed", () => {
  // WHY: severity drift would silently downgrade a DoS finding.
  const r = GRAPHQL_RULES.find((x) => x.id === "graphql-no-depth-limit")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: textbook resolver pulling from db.users with no context.user check.
test("graphql-resolver-no-auth: resolver hitting db.users without context.user is flagged", () => {
  const code = `
    const resolvers = {
      Query: {
        listUsers: (parent, args, context) => {
          return db.users.findMany();
        },
      },
    };
  `;
  assert.equal(fire(code, "graphql-resolver-no-auth"), true);
});

// WHY: same resolver shape but with context.user gate must not flag.
test("graphql-resolver-no-auth: resolver guarded by context.user is NOT flagged", () => {
  const code = `
    const resolvers = {
      Query: {
        listUsers: (parent, args, context) => {
          if (!context.user) throw new Error('UNAUTHENTICATED');
          return db.users.findMany();
        },
      },
    };
  `;
  assert.equal(fire(code, "graphql-resolver-no-auth"), false);
});

test("graphql-resolver-no-auth: metadata is well-formed", () => {
  // WHY: lock severity at high; broken access control on user table is not medium.
  const r = GRAPHQL_RULES.find((x) => x.id === "graphql-resolver-no-auth")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: mutation resolver with no auth check anywhere in body is the canonical hit.
test("graphql-mutation-no-auth: bare mutation resolver is flagged", () => {
  const code = `
    const resolvers = {
      Mutation: {
        deleteAccount: (parent, args, context) => {
          return db.account.delete({ where: { id: args.id } });
        },
      },
    };
  `;
  assert.equal(fire(code, "graphql-mutation-no-auth"), true);
});

// WHY: requireAuth(context) inside the body must suppress.
test("graphql-mutation-no-auth: mutation calling requireAuth(context) is NOT flagged", () => {
  const code = `
    const resolvers = {
      Mutation: {
        deleteAccount: (parent, args, context) => {
          requireAuth(context);
          return db.account.delete({ where: { id: args.id } });
        },
      },
    };
  `;
  assert.equal(fire(code, "graphql-mutation-no-auth"), false);
});

test("graphql-mutation-no-auth: metadata is well-formed", () => {
  // WHY: keep severity high — unauth mutations are state-changing.
  const r = GRAPHQL_RULES.find((x) => x.id === "graphql-mutation-no-auth")!;
  assert.equal(r.severity, "high");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: createYoga init with no complexity plugin at all should fire.
test("graphql-no-query-complexity: yoga init without cost analysis is flagged", () => {
  const code = `const yoga = createYoga({ schema, graphiql: false });`;
  assert.equal(fire(code, "graphql-no-query-complexity"), true);
});

// WHY: presence of `costAnalysis`/`maxComplexity` should suppress the rule.
test("graphql-no-query-complexity: yoga init with maxComplexity is NOT flagged", () => {
  const code = `const yoga = createYoga({ schema, plugins: [useCostLimit({ maxComplexity: 1000 })] });`;
  assert.equal(fire(code, "graphql-no-query-complexity"), false);
});

test("graphql-no-query-complexity: metadata is well-formed", () => {
  // WHY: medium is the right tier — quality-of-service issue, not direct RCE.
  const r = GRAPHQL_RULES.find((x) => x.id === "graphql-no-query-complexity")!;
  assert.equal(r.severity, "medium");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});

// WHY: an executor receiving an `operations` array with no length check is the
// canonical batching abuse shape.
test("graphql-batching-no-limit: executeBatch(operations) without cap is flagged", () => {
  const code = `const results = await executeBatch(operations);`;
  assert.equal(fire(code, "graphql-batching-no-limit"), true);
});

// WHY: presence of a length cap should suppress.
test("graphql-batching-no-limit: capped batch (length check) is NOT flagged", () => {
  const code = `if (operations.length > 10) throw new Error('too many'); const results = await executeBatch(operations);`;
  assert.equal(fire(code, "graphql-batching-no-limit"), false);
});

test("graphql-batching-no-limit: metadata is well-formed", () => {
  // WHY: lock severity at medium — DoS / amplification, not direct RCE.
  const r = GRAPHQL_RULES.find((x) => x.id === "graphql-batching-no-limit")!;
  assert.equal(r.severity, "medium");
  assert.match(r.owasp ?? "", /^A0\d:202\d\b/);
});
