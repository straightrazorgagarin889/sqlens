<?php
/**
 * MySQLi Framework Test Cases
 * Tests: procedural and OOP style, prepare, real_query
 */

// --- SAFE QUERIES ---

// OOP style with prepare
$stmt = $mysqli->prepare("SELECT username, email FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();

// Simple literal query
$mysqli->query("SELECT COUNT(*) as total FROM orders WHERE status = 'completed'");

// Prepared INSERT
$stmt = $mysqli->prepare("INSERT INTO audit_log (user_id, action, ip_address) VALUES (?, ?, ?)");
$stmt->bind_param("iss", $userId, $action, $ipAddress);
$stmt->execute();


// --- UNSAFE QUERIES ---

// Direct superglobal injection
$mysqli->query("SELECT * FROM users WHERE username = '" . $_POST['username'] . "'");

// real_query with user input
$mysqli->real_query("UPDATE users SET email = '" . $_GET['email'] . "' WHERE id = " . $_GET['id']);

// String interpolation vulnerability
$name = $_REQUEST['name'];
$mysqli->query("DELETE FROM users WHERE name = '$name'");


// --- ANTI-PATTERNS ---

// SELECT * with NULL comparison
$mysqli->query("SELECT * FROM orders WHERE cancelled_at != NULL");

// Multiple OR clauses
$mysqli->query("SELECT id FROM tags WHERE name = 'php' OR name = 'sql' OR name = 'mysql' OR name = 'security'");
