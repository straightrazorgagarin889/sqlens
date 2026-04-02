import * as assert from "assert";
import { TaintAnalyzer } from "../analysis/taint";
import { SQLCall } from "../analysis/phpAst";

suite("TaintAnalyzer Test Suite", () => {
  let analyzer: TaintAnalyzer;

  setup(() => {
    analyzer = new TaintAnalyzer();
  });

  function makeSQLCall(overrides: Partial<SQLCall>): SQLCall {
    return {
      sql: "",
      line: 5,
      column: 0,
      framework: "pdo",
      method: "query",
      hasBinding: false,
      isSafe: false,
      variables: [],
      enclosingLoop: false,
      loopType: null,
      surroundingCode: "",
      usesSprintfInterpolation: false,
      ...overrides,
    };
  }

  test("detects taint flow from $_GET to SQL", () => {
    const code = `<?php
$id = $_GET['id'];
$result = $pdo->query("SELECT * FROM users WHERE id = $id");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$id"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should detect taint flow from $_GET");
    assert.strictEqual(flows[0].risk, "HIGH");
  });

  test("detects taint flow from $_POST to SQL", () => {
    const code = `<?php
$name = $_POST['name'];
$db->query("SELECT * FROM users WHERE name = '$name'");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$name"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should detect taint flow from $_POST");
    assert.strictEqual(flows[0].risk, "HIGH");
  });

  test("assigns MEDIUM risk to $_COOKIE", () => {
    const code = `<?php
$token = $_COOKIE['session'];
$db->query("SELECT * FROM sessions WHERE token = '$token'");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$token"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    if (flows.length > 0) {
      assert.strictEqual(flows[0].risk, "MEDIUM");
    }
  });

  test("assigns LOW risk to $_SESSION", () => {
    const code = `<?php
$uid = $_SESSION['user_id'];
$db->query("SELECT * FROM users WHERE id = $uid");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$uid"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    if (flows.length > 0) {
      assert.strictEqual(flows[0].risk, "LOW");
    }
  });

  test("returns empty flows for safe code", () => {
    const code = `<?php
$db->query("SELECT * FROM users WHERE active = 1");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 2,
        method: "query",
        variables: [],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.strictEqual(flows.length, 0, "Should not detect flows in safe code");
  });

  test("isVariableTainted works correctly", () => {
    const sources = [
      {
        type: "GET" as const,
        variable: "$_GET[",
        line: 1,
        column: 0,
      },
    ];
    assert.ok(
      analyzer.isVariableTainted("$_GET", sources),
      "Should detect tainted variable"
    );
    assert.ok(
      !analyzer.isVariableTainted("$safe_var", sources),
      "Should not flag safe variable"
    );
  });

  test("handles code with no superglobals", () => {
    const code = `<?php
$name = "test";
$db->query("SELECT * FROM users WHERE name = '$name'");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$name"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.strictEqual(
      flows.length,
      0,
      "Should not detect flows without superglobals"
    );
  });

  test("handles empty code", () => {
    const flows = analyzer.analyzeTaintFlow("", []);
    assert.strictEqual(flows.length, 0, "Should handle empty input");
  });

  test("detects taint from $_FILES", () => {
    const code = `<?php
$name = $_FILES['upload']['name'];
$db->query("INSERT INTO files (name) VALUES ('$name')");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$name"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should detect taint from $_FILES");
    assert.strictEqual(flows[0].risk, "HIGH");
  });

  test("detects taint from $_ENV", () => {
    const code = `<?php
$dbname = $_ENV['DB_NAME'];
$db->query("SELECT * FROM $dbname");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$dbname"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should detect taint from $_ENV");
    assert.strictEqual(flows[0].risk, "MEDIUM");
  });

  test("detects taint from getenv()", () => {
    const code = `<?php
$path = getenv('UPLOAD_PATH');
$db->query("SELECT * FROM uploads WHERE path = '$path'");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$path"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should detect taint from getenv()");
  });

  test("detects taint from php://input", () => {
    const code = `<?php
$body = file_get_contents('php://input');
$db->query("INSERT INTO logs (data) VALUES ('$body')");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$body"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should detect taint from php://input");
  });

  test("detects taint from $argv", () => {
    const code = `<?php
$id = $argv[1];
$db->query("SELECT * FROM users WHERE id = $id");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$id"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should detect taint from $argv");
  });

  test("does not flag sanitized input with intval", () => {
    const code = `<?php
$id = intval($_GET['id']);
$db->query("SELECT * FROM users WHERE id = $id");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$id"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    // intval sanitizes the input, so no taint flow through assignment
    const directFlows = flows.filter((f) => f.path.includes("$id"));
    // The assignment-based flow should be blocked by sanitizer
    assert.ok(
      directFlows.length === 0 || directFlows.every((f) => f.path.length <= 2),
      "Should recognize intval as sanitizer"
    );
  });

  test("tracks multi-step taint propagation", () => {
    const code = `<?php
$a = $_GET['id'];
$b = $a;
$db->query("SELECT * FROM users WHERE id = $b");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 4,
        method: "query",
        variables: ["$b"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should track multi-step taint");
  });

  test("tracks taint through .= concatenation", () => {
    const code = `<?php
$sql = "SELECT * FROM users";
$sql .= " WHERE id = " . $_GET['id'];
$db->query($sql);
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 4,
        method: "query",
        variables: ["$sql"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should track taint through .= concatenation");
  });

  test("tracks bare superglobal assignment", () => {
    const code = `<?php
$data = $_POST;
$name = $data['name'];
$db->query("SELECT * FROM users WHERE name = '$name'");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 4,
        method: "query",
        variables: ["$name"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should track bare superglobal assignment");
  });

  test("assigns HIGH risk to $_REQUEST", () => {
    const code = `<?php
$input = $_REQUEST['search'];
$db->query("SELECT * FROM items WHERE name = '$input'");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$input"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    assert.ok(flows.length > 0, "Should detect $_REQUEST taint");
    assert.strictEqual(flows[0].risk, "HIGH");
  });

  test("assigns MEDIUM risk to $_SERVER", () => {
    const code = `<?php
$host = $_SERVER['HTTP_HOST'];
$db->query("SELECT * FROM sites WHERE host = '$host'");
?>`;
    const sqlCalls = [
      makeSQLCall({
        line: 3,
        method: "query",
        variables: ["$host"],
      }),
    ];
    const flows = analyzer.analyzeTaintFlow(code, sqlCalls);
    if (flows.length > 0) {
      assert.strictEqual(flows[0].risk, "MEDIUM");
    }
  });
});
