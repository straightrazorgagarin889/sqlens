import * as assert from "assert";
import { RuleRegistry } from "../analysis/rules/index";
import { SQLCall } from "../analysis/phpAst";

suite("RuleRegistry Configuration Test Suite", () => {
  function makeSQLCall(overrides: Partial<SQLCall>): SQLCall {
    return {
      sql: "",
      line: 1,
      column: 0,
      framework: "pdo",
      method: "query",
      hasBinding: false,
      isSafe: true,
      variables: [],
      enclosingLoop: false,
      loopType: null,
      surroundingCode: "",
      usesSprintfInterpolation: false,
      ...overrides,
    };
  }

  test("filters disabled rules", () => {
    const registry = new RuleRegistry(["SELECT_STAR"]);
    const call = makeSQLCall({ sql: "SELECT * FROM users" });
    const patterns = registry.runAll(call);
    const selectStar = patterns.find(p => p.type === "SELECT_STAR");
    assert.ok(!selectStar, "SELECT_STAR should be filtered when disabled");
  });

  test("returns all rules when no rules disabled", () => {
    const registry = new RuleRegistry([]);
    const call = makeSQLCall({ sql: "SELECT * FROM users" });
    const patterns = registry.runAll(call);
    const selectStar = patterns.find(p => p.type === "SELECT_STAR");
    assert.ok(selectStar, "SELECT_STAR should be present when not disabled");
  });

  test("filters multiple disabled rules", () => {
    const registry = new RuleRegistry(["SELECT_STAR", "NULL_COMPARISON"]);
    const call = makeSQLCall({ sql: "SELECT * FROM users WHERE deleted_at = NULL" });
    const patterns = registry.runAll(call);
    assert.ok(!patterns.find(p => p.type === "SELECT_STAR"), "SELECT_STAR should be filtered");
    assert.ok(!patterns.find(p => p.type === "NULL_COMPARISON"), "NULL_COMPARISON should be filtered");
  });

  test("default constructor works without arguments", () => {
    const registry = new RuleRegistry();
    const call = makeSQLCall({ sql: "SELECT * FROM users" });
    const patterns = registry.runAll(call);
    assert.ok(patterns.find(p => p.type === "SELECT_STAR"), "Should work with default constructor");
  });
});
