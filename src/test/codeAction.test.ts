import * as assert from "assert";
import { computeQuickFixes } from "../providers/codeActionProvider";

suite("CodeAction QuickFix Test Suite", () => {
  // ---- NULL_COMPARISON fixes ----

  test("fixes = NULL to IS NULL", () => {
    const fixes = computeQuickFixes(
      "SELECT * FROM users WHERE status = NULL",
      "NULL_COMPARISON"
    );
    assert.ok(fixes.length > 0, "Should produce a fix");
    assert.ok(fixes[0].newText.includes("IS NULL"), "Should contain IS NULL");
    assert.ok(!fixes[0].newText.includes("= NULL"), "Should not contain = NULL");
  });

  test("fixes != NULL to IS NOT NULL", () => {
    const fixes = computeQuickFixes(
      "SELECT * FROM users WHERE status != NULL",
      "NULL_COMPARISON"
    );
    assert.ok(fixes.length > 0, "Should produce a fix");
    assert.ok(fixes[0].newText.includes("IS NOT NULL"), "Should contain IS NOT NULL");
  });

  test("fixes <> NULL to IS NOT NULL", () => {
    const fixes = computeQuickFixes(
      "SELECT * FROM users WHERE status <> NULL",
      "NULL_COMPARISON"
    );
    assert.ok(fixes.length > 0, "Should produce a fix");
    assert.ok(fixes[0].newText.includes("IS NOT NULL"), "Should contain IS NOT NULL");
  });

  test("handles multiple NULL comparisons in one query", () => {
    const fixes = computeQuickFixes(
      "SELECT * FROM users WHERE a = NULL AND b != NULL",
      "NULL_COMPARISON"
    );
    assert.ok(fixes.length > 0, "Should produce a fix");
    assert.ok(fixes[0].newText.includes("IS NULL"), "Should fix = NULL");
    assert.ok(fixes[0].newText.includes("IS NOT NULL"), "Should fix != NULL");
  });

  test("returns empty for already correct IS NULL", () => {
    const fixes = computeQuickFixes(
      "SELECT * FROM users WHERE status IS NULL",
      "NULL_COMPARISON"
    );
    assert.strictEqual(fixes.length, 0, "Should not produce fix for correct syntax");
  });

  // ---- UNION_VS_UNION_ALL fixes ----

  test("fixes UNION to UNION ALL", () => {
    const fixes = computeQuickFixes(
      "SELECT id FROM a UNION SELECT id FROM b",
      "UNION_VS_UNION_ALL"
    );
    assert.ok(fixes.length > 0, "Should produce a fix");
    assert.ok(fixes[0].newText.includes("UNION ALL"), "Should contain UNION ALL");
  });

  test("does not break existing UNION ALL", () => {
    const fixes = computeQuickFixes(
      "SELECT id FROM a UNION ALL SELECT id FROM b",
      "UNION_VS_UNION_ALL"
    );
    assert.strictEqual(fixes.length, 0, "Should not produce fix for UNION ALL");
  });

  test("fixes multiple UNIONs", () => {
    const fixes = computeQuickFixes(
      "SELECT id FROM a UNION SELECT id FROM b UNION SELECT id FROM c",
      "UNION_VS_UNION_ALL"
    );
    assert.ok(fixes.length > 0, "Should produce a fix");
    // Count occurrences of UNION ALL
    const matches = fixes[0].newText.match(/UNION ALL/g);
    assert.strictEqual(matches?.length, 2, "Should fix both UNIONs");
  });

  // ---- REDUNDANT_DISTINCT fixes ----

  test("fixes REDUNDANT_DISTINCT by removing DISTINCT", () => {
    const fixes = computeQuickFixes(
      "SELECT DISTINCT dept, COUNT(*) FROM employees GROUP BY dept",
      "REDUNDANT_DISTINCT"
    );
    assert.ok(fixes.length > 0, "Should produce a fix");
    assert.ok(!fixes[0].newText.includes("DISTINCT"), "Should not contain DISTINCT");
    assert.ok(fixes[0].newText.startsWith("SELECT"), "Should start with SELECT");
  });

  // ---- Unsupported rules ----

  test("returns empty for unsupported rule type", () => {
    const fixes = computeQuickFixes("SELECT * FROM users", "SELECT_STAR");
    assert.strictEqual(fixes.length, 0, "Should not produce fix for unsupported rule");
  });

  test("returns empty for unknown rule type", () => {
    const fixes = computeQuickFixes("SELECT * FROM users", "UNKNOWN_RULE");
    assert.strictEqual(fixes.length, 0, "Should not produce fix for unknown rule");
  });
});
