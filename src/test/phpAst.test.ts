import * as assert from "assert";
import { PHPASTAnalyzer } from "../analysis/phpAst";

suite("PHPASTAnalyzer Test Suite", () => {
  let analyzer: PHPASTAnalyzer;

  setup(() => {
    analyzer = new PHPASTAnalyzer();
  });

  test("detects PDO query", () => {
    const code = `<?php
      $pdo->query("SELECT * FROM users WHERE id = 1");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect at least one SQL call");
    assert.strictEqual(results[0].method, "query");
    assert.ok(results[0].sql.includes("SELECT"));
  });

  test("detects PDO prepare", () => {
    const code = `<?php
      $pdo->prepare("SELECT * FROM users WHERE id = ?");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect prepared statement");
    assert.strictEqual(results[0].method, "prepare");
    assert.ok(results[0].hasBinding, "prepare with 2nd arg should be binding");
  });

  test("detects ezSQL get_results", () => {
    const code = `<?php
      $db->get_results("SELECT name FROM users");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect ezSQL query");
    assert.strictEqual(results[0].method, "get_results");
    assert.strictEqual(results[0].framework, "ezsql");
  });

  test("detects WordPress wpdb query", () => {
    const code = `<?php
      $wpdb->get_results("SELECT * FROM wp_posts");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect WordPress query");
  });

  test("extracts variables from concatenated SQL", () => {
    const code = `<?php
      $pdo->query("SELECT * FROM users WHERE id = " . $id);
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect concatenated SQL query");
    assert.ok(
      Array.isArray(results[0].variables),
      "Should return variables array"
    );
  });

  test("detects unsafe query with superglobals in SQL string", () => {
    const code = `<?php
      $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect query with superglobal");
    assert.strictEqual(results[0].isSafe, false, "Should detect unsafe query");
  });

  test("returns empty array for non-PHP code", () => {
    const code = "This is not PHP code";
    const results = analyzer.analyzePHPCode(code);
    assert.strictEqual(results.length, 0, "Should return empty for invalid PHP");
  });

  test("handles empty input", () => {
    const results = analyzer.analyzePHPCode("");
    assert.strictEqual(results.length, 0, "Should handle empty input");
  });

  test("detects multiple queries in one file", () => {
    const code = `<?php
      $pdo->query("SELECT * FROM users");
      $pdo->query("SELECT * FROM posts");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length >= 2, "Should detect multiple queries");
  });

  test("detects encapsed string variables", () => {
    const code = `<?php
      $pdo->query("SELECT * FROM users WHERE name = '$name'");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect query with encapsed string");
    assert.ok(results[0].sql.length > 0, "Should extract encapsed string");
  });

  test("detects MySQLi real_query", () => {
    const code = `<?php
      $mysqli->real_query("SELECT * FROM users");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect MySQLi real_query");
    assert.strictEqual(results[0].framework, "mysqli");
    assert.strictEqual(results[0].method, "real_query");
  });

  test("detects MySQLi multi_query", () => {
    const code = `<?php
      $mysqli->multi_query("SELECT * FROM users; SELECT * FROM posts");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect MySQLi multi_query");
    assert.strictEqual(results[0].framework, "mysqli");
  });

  test("detects MySQLi by object name hint", () => {
    const code = `<?php
      $mysqli->query("SELECT * FROM users");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect MySQLi query by name");
    assert.strictEqual(results[0].framework, "mysqli");
  });

  test("detects Laravel DB::select", () => {
    const code = `<?php
      DB::select("SELECT * FROM users WHERE id = ?", [1]);
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect Laravel DB::select");
    assert.strictEqual(results[0].framework, "laravel-db");
  });

  test("detects Laravel DB::raw", () => {
    const code = `<?php
      DB::raw("SELECT * FROM users");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect Laravel DB::raw");
    assert.strictEqual(results[0].framework, "laravel-db");
  });

  test("detects ezSQL get_col", () => {
    const code = `<?php
      $db->get_col("SELECT name FROM users");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect ezSQL get_col");
    assert.strictEqual(results[0].method, "get_col");
    assert.strictEqual(results[0].framework, "ezsql");
  });

  test("detects ezSQL insert method", () => {
    const code = `<?php
      $db->insert("INSERT INTO users (name) VALUES ('test')");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect ezSQL insert");
    assert.strictEqual(results[0].method, "insert");
    assert.strictEqual(results[0].framework, "ezsql");
  });

  test("detects ezSQL update method", () => {
    const code = `<?php
      $db->update("UPDATE users SET name = 'test' WHERE id = 1");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect ezSQL update");
    assert.strictEqual(results[0].method, "update");
  });

  test("detects ezSQL delete method", () => {
    const code = `<?php
      $db->delete("DELETE FROM users WHERE id = 1");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect ezSQL delete");
    assert.strictEqual(results[0].method, "delete");
  });

  test("detects sprintf SQL extraction", () => {
    const code = `<?php
      $db->query(sprintf("SELECT * FROM users WHERE id = %d", $id));
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect sprintf SQL");
    assert.ok(results[0].sql.includes("SELECT"), "Should extract SQL from sprintf");
    assert.ok(results[0].usesSprintfInterpolation, "Should detect sprintf interpolation");
  });

  test("detects query inside foreach loop", () => {
    const code = `<?php
    foreach ($ids as $id) {
      $pdo->query("SELECT * FROM users WHERE id = 1");
    }
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect query in loop");
    assert.ok(results[0].enclosingLoop, "Should mark as in loop");
    assert.strictEqual(results[0].loopType, "foreach");
  });

  test("detects query inside for loop", () => {
    const code = `<?php
    for ($i = 0; $i < 10; $i++) {
      $pdo->query("SELECT * FROM users WHERE id = 1");
    }
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect query in for loop");
    assert.ok(results[0].enclosingLoop, "Should mark as in loop");
    assert.strictEqual(results[0].loopType, "for");
  });

  test("detects query inside while loop", () => {
    const code = `<?php
    while ($row = $result->fetch()) {
      $pdo->query("SELECT * FROM orders WHERE user_id = 1");
    }
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect query in while loop");
    assert.ok(results[0].enclosingLoop, "Should mark as in loop");
    assert.strictEqual(results[0].loopType, "while");
  });

  test("detects chained $this->wpdb->method()", () => {
    const code = `<?php
      $this->wpdb->get_results("SELECT * FROM wp_posts");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect chained wpdb");
    assert.strictEqual(results[0].framework, "wordpress");
  });

  test("detects WordPress get_col", () => {
    const code = `<?php
      $wpdb->get_col("SELECT name FROM wp_users");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect WordPress get_col");
    assert.strictEqual(results[0].framework, "wordpress");
    assert.strictEqual(results[0].method, "get_col");
  });

  test("resolves SQL from variable assignment", () => {
    const code = `<?php
      $sql = "SELECT * FROM users WHERE active = 1";
      $pdo->query($sql);
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect query with variable SQL");
    assert.ok(results[0].sql.includes("SELECT"), "Should resolve variable to SQL string");
  });

  test("detects query outside loop is not N+1", () => {
    const code = `<?php
      $pdo->query("SELECT * FROM users WHERE id = 1");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0);
    assert.strictEqual(results[0].enclosingLoop, false, "Should not mark as in loop");
  });

  test("detects ezSQL replace method", () => {
    const code = `<?php
      $db->replace("REPLACE INTO cache (key_name, value) VALUES ('k', 'v')");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect ezSQL replace");
    assert.strictEqual(results[0].method, "replace");
  });

  test("detects Doctrine createQuery", () => {
    const code = `<?php
      $query = $em->createQuery("SELECT u FROM User u WHERE u.active = 1");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect Doctrine createQuery");
    assert.strictEqual(results[0].framework, "doctrine");
    assert.strictEqual(results[0].method, "createQuery");
  });

  test("detects Doctrine executeQuery with binding", () => {
    const code = `<?php
      $conn->executeQuery("SELECT * FROM users WHERE id = ?", [$id]);
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect Doctrine executeQuery");
    assert.strictEqual(results[0].framework, "doctrine");
    assert.ok(results[0].hasBinding, "Should detect binding parameter");
  });

  test("detects Doctrine executeStatement", () => {
    const code = `<?php
      $conn->executeStatement("UPDATE users SET active = 0 WHERE id = ?", [$id]);
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect Doctrine executeStatement");
    assert.strictEqual(results[0].framework, "doctrine");
  });

  test("detects Doctrine fetchAllAssociative", () => {
    const code = `<?php
      $rows = $conn->fetchAllAssociative("SELECT * FROM users");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect Doctrine fetchAllAssociative");
    assert.strictEqual(results[0].framework, "doctrine");
  });

  test("detects Doctrine fetchOne", () => {
    const code = `<?php
      $value = $conn->fetchOne("SELECT COUNT(*) FROM users");
    ?>`;
    const results = analyzer.analyzePHPCode(code);
    assert.ok(results.length > 0, "Should detect Doctrine fetchOne");
    assert.strictEqual(results[0].framework, "doctrine");
  });
});
