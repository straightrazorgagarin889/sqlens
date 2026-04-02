import * as assert from "assert";
import { AntiPatternDetector } from "../analysis/antiPatterns";
import { SQLCall } from "../analysis/phpAst";

suite("AntiPatternDetector Test Suite", () => {
  let detector: AntiPatternDetector;

  setup(() => {
    detector = new AntiPatternDetector();
  });

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

  test("detects SELECT *", () => {
    const call = makeSQLCall({ sql: "SELECT * FROM users" });
    const patterns = detector.detectAntiPatterns(call);
    const selectStar = patterns.find((p) => p.type === "SELECT_STAR");
    assert.ok(selectStar, "Should detect SELECT *");
    assert.strictEqual(selectStar!.severity, "warning");
  });

  test("does not flag specific column select", () => {
    const call = makeSQLCall({ sql: "SELECT id, name FROM users" });
    const patterns = detector.detectAntiPatterns(call);
    const selectStar = patterns.find((p) => p.type === "SELECT_STAR");
    assert.ok(!selectStar, "Should not flag specific columns");
  });

  test("detects NULL comparison with =", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE deleted_at = NULL",
    });
    const patterns = detector.detectAntiPatterns(call);
    const nullComp = patterns.find((p) => p.type === "NULL_COMPARISON");
    assert.ok(nullComp, "Should detect = NULL");
    assert.strictEqual(nullComp!.severity, "error");
  });

  test("detects NULL comparison with !=", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE status != NULL",
    });
    const patterns = detector.detectAntiPatterns(call);
    const nullComp = patterns.find((p) => p.type === "NULL_COMPARISON");
    assert.ok(nullComp, "Should detect != NULL");
  });

  test("does not flag IS NULL", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE deleted_at IS NULL",
    });
    const patterns = detector.detectAntiPatterns(call);
    const nullComp = patterns.find((p) => p.type === "NULL_COMPARISON");
    assert.ok(!nullComp, "Should not flag IS NULL");
  });

  test("detects OR explosion (>3 OR clauses)", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE a = 1 OR b = 2 OR c = 3 OR d = 4",
    });
    const patterns = detector.detectAntiPatterns(call);
    const orExplosion = patterns.find((p) => p.type === "OR_EXPLOSION");
    assert.ok(orExplosion, "Should detect OR explosion");
    assert.strictEqual(orExplosion!.severity, "warning");
  });

  test("does not flag few OR clauses", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE a = 1 OR b = 2",
    });
    const patterns = detector.detectAntiPatterns(call);
    const orExplosion = patterns.find((p) => p.type === "OR_EXPLOSION");
    assert.ok(!orExplosion, "Should not flag 2 OR clauses");
  });

  test("detects SQL injection for unsafe query", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE id = $_GET['id']",
      isSafe: false,
    });
    const patterns = detector.detectAntiPatterns(call);
    const injection = patterns.find((p) => p.type === "SQL_INJECTION");
    assert.ok(injection, "Should detect SQL injection");
    assert.strictEqual(injection!.severity, "error");
  });

  test("does not flag safe query as injection", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE id = ?",
      isSafe: true,
      hasBinding: true,
    });
    const patterns = detector.detectAntiPatterns(call);
    const injection = patterns.find((p) => p.type === "SQL_INJECTION");
    assert.ok(!injection, "Should not flag safe query");
  });

  test("detects ezSQL missing escape", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE name = $_POST['name']",
      framework: "ezsql",
      method: "get_results",
      isSafe: false,
    });
    const patterns = detector.detectAntiPatterns(call);
    const noEscape = patterns.find((p) => p.type === "EZSQL_NO_ESCAPE");
    assert.ok(noEscape, "Should detect missing escape in ezSQL");
  });

  test("detects ezSQL cache bypass with RAND()", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users ORDER BY RAND()",
      framework: "ezsql",
      method: "query",
    });
    const patterns = detector.detectAntiPatterns(call);
    const cacheBypass = patterns.find((p) => p.type === "EZSQL_CACHE_BYPASS");
    assert.ok(cacheBypass, "Should detect RAND() cache bypass");
  });

  test("detects ezSQL error suppression", () => {
    const call = makeSQLCall({
      sql: "",
      framework: "ezsql",
      method: "hide_errors",
    });
    const patterns = detector.detectAntiPatterns(call);
    const suppression = patterns.find(
      (p) => p.type === "EZSQL_ERROR_SUPPRESSION"
    );
    assert.ok(suppression, "Should detect error suppression");
  });

  test("detects ezSQL deprecated methods", () => {
    const call = makeSQLCall({
      sql: "",
      framework: "ezsql",
      method: "debug",
    });
    const patterns = detector.detectAntiPatterns(call);
    const deprecated = patterns.find(
      (p) => p.type === "EZSQL_DEPRECATED_METHOD"
    );
    assert.ok(deprecated, "Should detect deprecated method");
  });

  test("detects function on indexed column in WHERE", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE YEAR(users.created_at) = 2024",
    });
    const patterns = detector.detectAntiPatterns(call);
    const funcOnCol = patterns.find((p) => p.type === "FUNCTION_ON_COLUMN");
    assert.ok(funcOnCol, "Should detect function applied to column in WHERE");
  });

  // ---- Security Rules ----

  test("detects sprintf taint with %s", () => {
    const call = makeSQLCall({
      sql: "SELECT COUNT(*) FROM users WHERE name = '%s'",
      usesSprintfInterpolation: true,
      surroundingCode: 'sprintf("SELECT COUNT(*) FROM users WHERE name = \'%s\'", $name)',
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "SPRINTF_TAINT");
    assert.ok(found, "Should detect sprintf taint");
  });

  test("detects deprecated mysql_* functions", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users",
      surroundingCode: 'mysql_query("SELECT * FROM users")',
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "DEPRECATED_MYSQL");
    assert.ok(found, "Should detect deprecated mysql_*");
  });

  test("detects WordPress without prepare", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM wp_posts WHERE status = 'publish'",
      framework: "wordpress",
      method: "get_results",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "WPDB_NO_PREPARE");
    assert.ok(found, "Should detect wpdb without prepare");
  });

  test("does not flag WordPress prepare method", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM wp_posts WHERE status = %s",
      framework: "wordpress",
      method: "prepare",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "WPDB_NO_PREPARE");
    assert.ok(!found, "Should not flag prepare method");
  });

  test("detects Laravel raw without binding", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users ORDER BY name",
      framework: "laravel-db",
      method: "raw",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "LARAVEL_RAW_NO_BINDING");
    assert.ok(found, "Should detect Laravel raw without binding");
  });

  test("does not flag Laravel raw with binding", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE id = ?",
      framework: "laravel-db",
      method: "raw",
      hasBinding: true,
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "LARAVEL_RAW_NO_BINDING");
    assert.ok(!found, "Should not flag raw with binding");
  });

  test("detects stacked queries", () => {
    const call = makeSQLCall({
      sql: "SELECT 1; DROP TABLE users",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "STACKED_QUERIES");
    assert.ok(found, "Should detect stacked queries");
  });

  test("detects file operations", () => {
    const call = makeSQLCall({
      sql: "SELECT LOAD_FILE('/etc/passwd')",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "FILE_OPERATION");
    assert.ok(found, "Should detect file operation");
  });

  test("detects INTO OUTFILE", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users INTO OUTFILE '/tmp/data.csv'",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "FILE_OPERATION");
    assert.ok(found, "Should detect INTO OUTFILE");
  });

  test("detects DDL in app code", () => {
    const call = makeSQLCall({
      sql: "GRANT ALL PRIVILEGES ON *.* TO 'user'@'%'",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "DDL_IN_APP");
    assert.ok(found, "Should detect GRANT in app code");
  });

  test("detects timing attack", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE id = 1 AND SLEEP(5)",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "TIMING_ATTACK");
    assert.ok(found, "Should detect SLEEP timing attack");
  });

  test("detects BENCHMARK timing attack", () => {
    const call = makeSQLCall({
      sql: "SELECT BENCHMARK(1000000, SHA1('test'))",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "TIMING_ATTACK");
    assert.ok(found, "Should detect BENCHMARK timing attack");
  });

  test("detects information_schema access", () => {
    const call = makeSQLCall({
      sql: "SELECT table_name FROM information_schema.tables",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "INFO_SCHEMA_ACCESS");
    assert.ok(found, "Should detect information_schema access");
  });

  // ---- Safety Rules ----

  test("detects UPDATE without WHERE", () => {
    const call = makeSQLCall({
      sql: "UPDATE users SET active = 0",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "UPDATE_NO_WHERE");
    assert.ok(found, "Should detect UPDATE without WHERE");
    assert.strictEqual(found!.severity, "error");
  });

  test("does not flag UPDATE with WHERE", () => {
    const call = makeSQLCall({
      sql: "UPDATE users SET active = 0 WHERE id = 1",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "UPDATE_NO_WHERE");
    assert.ok(!found, "Should not flag UPDATE with WHERE");
  });

  test("detects DELETE without WHERE", () => {
    const call = makeSQLCall({
      sql: "DELETE FROM sessions",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "DELETE_NO_WHERE");
    assert.ok(found, "Should detect DELETE without WHERE");
    assert.strictEqual(found!.severity, "error");
  });

  test("does not flag DELETE with WHERE", () => {
    const call = makeSQLCall({
      sql: "DELETE FROM sessions WHERE expired_at < NOW()",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "DELETE_NO_WHERE");
    assert.ok(!found, "Should not flag DELETE with WHERE");
  });

  test("detects DROP TABLE", () => {
    const call = makeSQLCall({
      sql: "DROP TABLE IF EXISTS temp_data",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "DESTRUCTIVE_DDL");
    assert.ok(found, "Should detect DROP TABLE");
  });

  test("detects TRUNCATE TABLE", () => {
    const call = makeSQLCall({
      sql: "TRUNCATE TABLE logs",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "DESTRUCTIVE_DDL");
    assert.ok(found, "Should detect TRUNCATE");
  });

  test("detects INSERT without column list", () => {
    const call = makeSQLCall({
      sql: "INSERT INTO users VALUES (1, 'John', 'john@example.com')",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "INSERT_NO_COLUMNS");
    assert.ok(found, "Should detect INSERT without columns");
  });

  test("does not flag INSERT with column list", () => {
    const call = makeSQLCall({
      sql: "INSERT INTO users (id, name, email) VALUES (1, 'John', 'john@example.com')",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "INSERT_NO_COLUMNS");
    assert.ok(!found, "Should not flag INSERT with columns");
  });

  test("detects error disclosure", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users",
      surroundingCode: 'die(mysql_error());',
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "ERROR_DISCLOSURE");
    assert.ok(found, "Should detect error disclosure");
  });

  test("detects REPLACE INTO statement", () => {
    const call = makeSQLCall({
      sql: "REPLACE INTO users (id, name) VALUES (1, 'John')",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "REPLACE_STATEMENT");
    assert.ok(found, "Should detect REPLACE INTO");
  });

  test("detects ALTER TABLE DROP COLUMN", () => {
    const call = makeSQLCall({
      sql: "ALTER TABLE users DROP COLUMN email",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "ALTER_DROP_COLUMN");
    assert.ok(found, "Should detect ALTER DROP COLUMN");
  });

  // ---- Performance Rules ----

  test("detects ORDER BY RAND()", () => {
    const call = makeSQLCall({
      sql: "SELECT id, name FROM users ORDER BY RAND() LIMIT 5",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "ORDER_BY_RAND");
    assert.ok(found, "Should detect ORDER BY RAND()");
  });

  test("detects leading wildcard LIKE", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM products WHERE name LIKE '%phone%'",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "LEADING_WILDCARD");
    assert.ok(found, "Should detect leading wildcard");
  });

  test("does not flag trailing wildcard LIKE", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM products WHERE name LIKE 'phone%'",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "LEADING_WILDCARD");
    assert.ok(!found, "Should not flag trailing wildcard");
  });

  test("detects large OFFSET", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM products ORDER BY id LIMIT 20 OFFSET 50000",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "LARGE_OFFSET");
    assert.ok(found, "Should detect large OFFSET");
  });

  test("does not flag small OFFSET", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM products ORDER BY id LIMIT 20 OFFSET 50",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "LARGE_OFFSET");
    assert.ok(!found, "Should not flag small OFFSET");
  });

  test("detects N+1 query in loop", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM orders WHERE user_id = 1",
      enclosingLoop: true,
      loopType: "foreach",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "N_PLUS_ONE");
    assert.ok(found, "Should detect N+1 query");
  });

  test("does not flag query outside loop", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM orders WHERE user_id = 1",
      enclosingLoop: false,
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "N_PLUS_ONE");
    assert.ok(!found, "Should not flag query outside loop");
  });

  test("detects cartesian join", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users, orders",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "CARTESIAN_JOIN");
    assert.ok(found, "Should detect cartesian join");
  });

  test("detects UNION without ALL", () => {
    const call = makeSQLCall({
      sql: "SELECT id FROM active_users UNION SELECT id FROM premium_users",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "UNION_VS_UNION_ALL");
    assert.ok(found, "Should detect UNION without ALL");
  });

  test("does not flag UNION ALL", () => {
    const call = makeSQLCall({
      sql: "SELECT id FROM active_users UNION ALL SELECT id FROM premium_users",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "UNION_VS_UNION_ALL");
    assert.ok(!found, "Should not flag UNION ALL");
  });

  test("detects COUNT for EXISTS", () => {
    const call = makeSQLCall({
      sql: "SELECT COUNT(*) FROM orders WHERE user_id = 1",
      surroundingCode: '$count = $db->get_var("..."); if ($count > 0) {',
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "COUNT_FOR_EXISTS");
    assert.ok(found, "Should detect COUNT for EXISTS");
  });

  test("detects old-style join", () => {
    const call = makeSQLCall({
      sql: "SELECT u.name, o.total FROM users u, orders o WHERE u.id = o.user_id",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "OLD_STYLE_JOIN");
    assert.ok(found, "Should detect old-style join");
  });

  test("detects correlated subquery", () => {
    const call = makeSQLCall({
      sql: "SELECT u.name, (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id) AS cnt FROM users u",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "CORRELATED_SUBQUERY");
    assert.ok(found, "Should detect correlated subquery");
  });

  // ---- Correctness Rules ----

  test("detects BETWEEN with date strings", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM orders WHERE created_at BETWEEN '2024-01-01' AND '2024-01-31'",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "BETWEEN_DATETIME");
    assert.ok(found, "Should detect BETWEEN with dates");
  });

  test("detects COUNT(column) semantics", () => {
    const call = makeSQLCall({
      sql: "SELECT COUNT(email) FROM users",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "COUNT_COLUMN_SEMANTICS");
    assert.ok(found, "Should detect COUNT(column)");
  });

  test("does not flag COUNT(*)", () => {
    const call = makeSQLCall({
      sql: "SELECT COUNT(*) FROM users",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "COUNT_COLUMN_SEMANTICS");
    assert.ok(!found, "Should not flag COUNT(*)");
  });

  test("detects HAVING without GROUP BY", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM orders HAVING total > 100",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "HAVING_NO_GROUP_BY");
    assert.ok(found, "Should detect HAVING without GROUP BY");
  });

  test("does not flag HAVING with GROUP BY", () => {
    const call = makeSQLCall({
      sql: "SELECT dept, COUNT(*) FROM employees GROUP BY dept HAVING COUNT(*) > 5",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "HAVING_NO_GROUP_BY");
    assert.ok(!found, "Should not flag HAVING with GROUP BY");
  });

  test("detects LIMIT without ORDER BY", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users LIMIT 10",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "LIMIT_NO_ORDER_BY");
    assert.ok(found, "Should detect LIMIT without ORDER BY");
  });

  test("does not flag LIMIT with ORDER BY", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users ORDER BY id LIMIT 10",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "LIMIT_NO_ORDER_BY");
    assert.ok(!found, "Should not flag LIMIT with ORDER BY");
  });

  test("detects NOT IN nullable risk", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE id NOT IN (SELECT manager_id FROM departments)",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "NOT_IN_NULLABLE");
    assert.ok(found, "Should detect NOT IN nullable");
  });

  test("detects redundant DISTINCT with GROUP BY", () => {
    const call = makeSQLCall({
      sql: "SELECT DISTINCT department, COUNT(*) FROM employees GROUP BY department",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "REDUNDANT_DISTINCT");
    assert.ok(found, "Should detect redundant DISTINCT");
  });

  test("does not flag DISTINCT without GROUP BY", () => {
    const call = makeSQLCall({
      sql: "SELECT DISTINCT name FROM users",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "REDUNDANT_DISTINCT");
    assert.ok(!found, "Should not flag DISTINCT without GROUP BY");
  });

  test("detects CASE without ELSE", () => {
    const call = makeSQLCall({
      sql: "SELECT name, CASE WHEN status = 1 THEN 'active' WHEN status = 2 THEN 'inactive' END AS label FROM users",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "CASE_NO_ELSE");
    assert.ok(found, "Should detect CASE without ELSE");
  });

  test("does not flag CASE with ELSE", () => {
    const call = makeSQLCall({
      sql: "SELECT CASE WHEN status = 1 THEN 'active' ELSE 'unknown' END FROM users",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "CASE_NO_ELSE");
    assert.ok(!found, "Should not flag CASE with ELSE");
  });

  test("detects mixed AND/OR without parentheses", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE active = 1 OR role = 'admin' AND verified = 1",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "MIXED_AND_OR_PRECEDENCE");
    assert.ok(found, "Should detect mixed AND/OR");
  });

  test("does not flag AND/OR with parentheses", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE (active = 1 OR role = 'admin') AND verified = 1",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "MIXED_AND_OR_PRECEDENCE");
    assert.ok(!found, "Should not flag parenthesized AND/OR");
  });

  // ---- Best Practice Rules ----

  test("detects deeply nested subqueries (suggest CTE)", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM (SELECT user_id FROM (SELECT * FROM orders) sub1) sub2",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "SUGGEST_CTE");
    assert.ok(found, "Should suggest CTE for nested subqueries");
  });

  test("detects missing prepared statement", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE id = $id",
      variables: ["$id"],
      isSafe: true,
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "SUGGEST_PREPARED_STMT");
    assert.ok(found, "Should suggest prepared statement");
  });

  test("does not suggest prepared stmt for bound query", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE id = ?",
      hasBinding: true,
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "SUGGEST_PREPARED_STMT");
    assert.ok(!found, "Should not suggest prepared stmt for bound query");
  });

  test("detects hardcoded credentials", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE password = 'admin123'",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "HARDCODED_CREDENTIALS");
    assert.ok(found, "Should detect hardcoded credentials");
  });

  test("detects plaintext password comparison", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE password = '$pass'",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "PLAINTEXT_PASSWORD");
    assert.ok(found, "Should detect plaintext password");
  });

  test("detects SUGGEST_KEYSET_PAGINATION", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM products ORDER BY id LIMIT 20 OFFSET 500",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "SUGGEST_KEYSET_PAGINATION");
    assert.ok(found, "Should suggest keyset pagination");
  });

  test("detects SELECT * in subquery (SUGGEST_EXPLICIT_COLUMNS)", () => {
    const call = makeSQLCall({
      sql: "SELECT id FROM (SELECT * FROM users WHERE active = 1) sub",
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "SUGGEST_EXPLICIT_COLUMNS");
    assert.ok(found, "Should suggest explicit columns in subquery");
  });

  test("detects FOR UPDATE without transaction", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE id = 1 FOR UPDATE",
      surroundingCode: '$pdo->query("SELECT * FROM users WHERE id = 1 FOR UPDATE");',
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "SELECT_FOR_UPDATE_NO_TX");
    assert.ok(found, "Should detect FOR UPDATE without transaction");
  });

  test("does not flag FOR UPDATE with transaction", () => {
    const call = makeSQLCall({
      sql: "SELECT * FROM users WHERE id = 1 FOR UPDATE",
      surroundingCode: '$pdo->beginTransaction(); $pdo->query("...");',
    });
    const patterns = detector.detectAntiPatterns(call);
    const found = patterns.find((p) => p.type === "SELECT_FOR_UPDATE_NO_TX");
    assert.ok(!found, "Should not flag FOR UPDATE with transaction");
  });
});
