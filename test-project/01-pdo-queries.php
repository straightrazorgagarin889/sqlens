<?php
/**
 * PDO Framework Test Cases
 * Tests: query detection, prepare, safe/unsafe patterns
 */

// --- SAFE QUERIES ---

// Basic SELECT with literal values
$pdo->query("SELECT id, name, email FROM users WHERE active = 1");

// Prepared statement with positional placeholders
$stmt = $pdo->prepare("SELECT * FROM orders WHERE user_id = ? AND status = ?");
$stmt->execute([$userId, $status]);

// Prepared statement with named placeholders
$stmt = $pdo->prepare("SELECT name FROM products WHERE price > :minPrice AND category = :cat");
$stmt->execute([':minPrice' => 100, ':cat' => 'electronics']);

// INSERT with prepare
$stmt = $pdo->prepare("INSERT INTO logs (action, created_at) VALUES (?, NOW())");
$stmt->execute([$action]);

// UPDATE with prepare
$stmt = $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
$stmt->execute([$userId]);

// DELETE with prepare
$stmt = $pdo->prepare("DELETE FROM sessions WHERE expires_at < NOW()");
$stmt->execute();


// --- UNSAFE QUERIES (should trigger warnings) ---

// Direct $_GET in query - HIGH RISK
$pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);

// Direct $_POST in query - HIGH RISK
$pdo->query("INSERT INTO comments (body) VALUES ('" . $_POST['comment'] . "')");

// Variable from $_REQUEST without sanitization
$search = $_REQUEST['q'];
$pdo->query("SELECT * FROM products WHERE name LIKE '%" . $search . "%'");

// $_COOKIE in query - MEDIUM RISK
$pdo->query("SELECT * FROM sessions WHERE token = '" . $_COOKIE['session_id'] . "'");


// --- ANTI-PATTERNS ---

// SELECT * (should warn)
$pdo->query("SELECT * FROM users");

// NULL comparison with = (should error)
$pdo->query("SELECT * FROM users WHERE deleted_at = NULL");

// OR explosion (should warn - more than 3 OR clauses)
$pdo->query("SELECT * FROM products WHERE category = 'a' OR category = 'b' OR category = 'c' OR category = 'd' OR category = 'e'");

// exec() usage
$pdo->exec("DROP TABLE IF EXISTS temp_data");
