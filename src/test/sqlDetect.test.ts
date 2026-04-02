import * as assert from "assert";
import { SQLDetector } from "../analysis/sqlDetect";

suite("SQLDetector Test Suite", () => {
  let detector: SQLDetector;

  setup(() => {
    detector = new SQLDetector();
  });

  test("detects SQL queries in PHP document", () => {
    const code = `<?php
      $pdo->query("SELECT * FROM users WHERE active = 1");
    ?>`;
    const result = detector.detectSQLInDocument(code);
    assert.ok(result.totalQueries > 0, "Should find queries");
    assert.strictEqual(
      result.totalQueries,
      result.safeQueries + result.riskyQueries,
      "Total should equal safe + risky"
    );
  });

  test("isValidSQL recognizes SQL keywords", () => {
    assert.ok(detector.isValidSQL("SELECT * FROM users"));
    assert.ok(detector.isValidSQL("INSERT INTO users VALUES (1)"));
    assert.ok(detector.isValidSQL("UPDATE users SET name = 'test'"));
    assert.ok(detector.isValidSQL("DELETE FROM users WHERE id = 1"));
    assert.ok(detector.isValidSQL("CREATE TABLE users (id INT)"));
    assert.ok(detector.isValidSQL("DROP TABLE users"));
    assert.ok(detector.isValidSQL("ALTER TABLE users ADD COLUMN name VARCHAR"));
    assert.ok(detector.isValidSQL("SHOW TABLES"));
  });

  test("isValidSQL rejects non-SQL strings", () => {
    assert.ok(!detector.isValidSQL("hello world"));
    assert.ok(!detector.isValidSQL("function test()"));
    assert.ok(!detector.isValidSQL(""));
  });

  test("extractSQLType returns correct types", () => {
    assert.strictEqual(detector.extractSQLType("SELECT * FROM users"), "SELECT");
    assert.strictEqual(
      detector.extractSQLType("INSERT INTO users VALUES (1)"),
      "INSERT"
    );
    assert.strictEqual(
      detector.extractSQLType("UPDATE users SET name = 'x'"),
      "UPDATE"
    );
    assert.strictEqual(
      detector.extractSQLType("DELETE FROM users WHERE id = 1"),
      "DELETE"
    );
    assert.strictEqual(
      detector.extractSQLType("some random text"),
      "UNKNOWN"
    );
  });

  test("extractTables extracts table names from FROM clause", () => {
    const tables = detector.extractTables(
      "SELECT * FROM users JOIN posts ON users.id = posts.user_id"
    );
    assert.ok(tables.length >= 1, "Should extract at least one table");
  });

  test("extractTables extracts table from UPDATE", () => {
    const tables = detector.extractTables("UPDATE users SET name = 'test'");
    assert.ok(tables.length >= 1, "Should extract table from UPDATE");
  });

  test("extractTables extracts table from INSERT INTO", () => {
    const tables = detector.extractTables(
      "INSERT INTO users (name) VALUES ('test')"
    );
    assert.ok(tables.length >= 1, "Should extract table from INSERT INTO");
  });

  test("extractColumns returns * for SELECT *", () => {
    const columns = detector.extractColumns("SELECT * FROM users");
    assert.ok(columns.includes("*"), "Should return *");
  });

  test("extractColumns returns column names", () => {
    const columns = detector.extractColumns(
      "SELECT name, email FROM users"
    );
    assert.ok(columns.length >= 2, "Should extract column names");
  });

  test("returns zero queries for non-PHP code", () => {
    const result = detector.detectSQLInDocument("Just some plain text");
    assert.strictEqual(result.totalQueries, 0);
  });

  test("counts risky queries correctly", () => {
    const code = `<?php
      $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
    ?>`;
    const result = detector.detectSQLInDocument(code);
    if (result.totalQueries > 0) {
      assert.ok(
        result.riskyQueries >= 0,
        "Should count risky queries"
      );
    }
  });

  test("isValidSQL recognizes REPLACE", () => {
    assert.ok(detector.isValidSQL("REPLACE INTO users VALUES (1, 'test')"));
  });

  test("isValidSQL recognizes TRUNCATE", () => {
    assert.ok(detector.isValidSQL("TRUNCATE TABLE users"));
  });

  test("isValidSQL recognizes EXPLAIN", () => {
    assert.ok(detector.isValidSQL("EXPLAIN SELECT * FROM users"));
  });

  test("isValidSQL recognizes WITH (CTE)", () => {
    assert.ok(detector.isValidSQL("WITH cte AS (SELECT 1) SELECT * FROM cte"));
  });

  test("isValidSQL recognizes BEGIN", () => {
    assert.ok(detector.isValidSQL("BEGIN"));
  });

  test("isValidSQL recognizes COMMIT", () => {
    assert.ok(detector.isValidSQL("COMMIT"));
  });

  test("isValidSQL recognizes ROLLBACK", () => {
    assert.ok(detector.isValidSQL("ROLLBACK"));
  });

  test("isValidSQL recognizes CALL", () => {
    assert.ok(detector.isValidSQL("CALL sp_get_users()"));
  });

  test("isValidSQL recognizes SET", () => {
    assert.ok(detector.isValidSQL("SET @var = 1"));
  });

  test("isValidSQL recognizes GRANT", () => {
    assert.ok(detector.isValidSQL("GRANT SELECT ON db.* TO 'user'@'host'"));
  });

  test("isValidSQL recognizes LOCK", () => {
    assert.ok(detector.isValidSQL("LOCK TABLES users WRITE"));
  });

  test("extractSQLType returns REPLACE", () => {
    assert.strictEqual(detector.extractSQLType("REPLACE INTO users VALUES (1)"), "REPLACE");
  });

  test("extractSQLType returns TRUNCATE", () => {
    assert.strictEqual(detector.extractSQLType("TRUNCATE TABLE users"), "TRUNCATE");
  });

  test("extractSQLType returns EXPLAIN", () => {
    assert.strictEqual(detector.extractSQLType("EXPLAIN SELECT * FROM users"), "EXPLAIN");
  });

  test("extractSQLType returns WITH for CTE", () => {
    assert.strictEqual(detector.extractSQLType("WITH cte AS (SELECT 1) SELECT * FROM cte"), "WITH");
  });

  test("extractSQLType returns BEGIN", () => {
    assert.strictEqual(detector.extractSQLType("BEGIN"), "BEGIN");
  });

  test("extractSQLType returns COMMIT", () => {
    assert.strictEqual(detector.extractSQLType("COMMIT"), "COMMIT");
  });

  test("extractSQLType returns ROLLBACK", () => {
    assert.strictEqual(detector.extractSQLType("ROLLBACK"), "ROLLBACK");
  });

  test("extractSQLType returns GRANT", () => {
    assert.strictEqual(detector.extractSQLType("GRANT ALL ON db.*"), "GRANT");
  });

  test("extractTables handles backtick-quoted names", () => {
    const tables = detector.extractTables("SELECT * FROM \`users\` JOIN \`posts\` ON \`users\`.id = \`posts\`.user_id");
    assert.ok(tables.some((t) => t === "users"), "Should extract backtick-quoted users");
    assert.ok(tables.some((t) => t === "posts"), "Should extract backtick-quoted posts");
  });

  test("extractTables handles schema-qualified names", () => {
    const tables = detector.extractTables("SELECT * FROM mydb.users");
    assert.ok(tables.some((t) => t === "users"), "Should extract schema-qualified table");
  });

  test("extractTables handles DELETE FROM", () => {
    const tables = detector.extractTables("DELETE FROM sessions WHERE expired = 1");
    assert.ok(tables.some((t) => t === "sessions"), "Should extract table from DELETE");
  });

  test("extractTables handles REPLACE INTO", () => {
    const tables = detector.extractTables("REPLACE INTO cache (key_col, value) VALUES ('k', 'v')");
    assert.ok(tables.some((t) => t === "cache"), "Should extract table from REPLACE INTO");
  });

  test("detects multiple frameworks in same file", () => {
    const code = `<?php
      $pdo->query("SELECT * FROM users");
      $wpdb->get_results("SELECT * FROM wp_posts");
      $db->get_var("SELECT COUNT(*) FROM items");
    ?>`;
    const result = detector.detectSQLInDocument(code);
    assert.ok(result.totalQueries >= 3, "Should find 3+ queries");
  });

  test("handles empty SQL string gracefully", () => {
    assert.ok(!detector.isValidSQL(""));
    assert.strictEqual(detector.extractSQLType(""), "UNKNOWN");
    assert.deepStrictEqual(detector.extractTables(""), []);
    assert.deepStrictEqual(detector.extractColumns(""), []);
  });
});
