# SQLens

A comprehensive VS Code extension for analyzing, visualizing, and optimizing SQL queries in PHP code. This extension helps developers identify potential security risks, performance issues, and provides intelligent insights for database queries.

## Features

### Core Capabilities

- **SQL Detection**: Automatically finds SQL queries in PHP code across multiple frameworks
- **Security Analysis**: Detects potential SQL injection vulnerabilities
- **Performance Insights**: Identifies anti-patterns and performance issues
- **Query Visualization**: Shows execution plans and query analysis
- **Multi-Framework Support**: Works with WordPress, Laravel, PDO, MySQLi, ezSQL and more

### Supported Frameworks

- **ezSQL**: `$db->get_results()`, `$db->get_row()`, `$db->get_var()`, `$db->get_col()`, `$db->query()`, `$db->escape()`, etc.
- **WordPress**: `$wpdb->get_results()`, `$wpdb->prepare()`, etc.
- **Laravel**: `DB::select()`, `DB::raw()`, etc.
- **PDO**: `$pdo->query()`, `$pdo->prepare()`, etc.
- **MySQLi**: `mysqli_query()`, `$mysqli->prepare()`, etc.

### Key Features

#### Intelligent Code Analysis

- Real-time PHP AST parsing to extract SQL queries
- Automatic detection of query frameworks and methods
- Context-aware analysis with taint tracking

#### Security Scanning

- SQL injection vulnerability detection
- Unsafe concatenation warnings
- Parameter binding validation
- Risk severity classification (High/Medium/Info)

#### Performance Analysis

- SELECT \* usage warnings
- NULL comparison anti-patterns (= NULL vs IS NULL)
- OR explosion detection
- Index usage recommendations

#### Query Visualization

- **Hover Information**: Quick summary with tables, columns, and safety status
- **CodeLens Integration**: Inline Preview/Explain/Copy actions
- **Side Panel**: Complete list of all queries in workspace
- **Explain Plans**: Visual execution plan analysis

#### Database Integration (Optional)

- Safe query preview (SELECT only, limited rows)
- EXPLAIN plan execution
- Schema discovery and caching
- Read-only connection security

## Configuration

### Basic Settings

```json
{
  "sqlens.enable": true,
  "sqlens.frameworks": [
    "pdo",
    "mysqli",
    "wordpress",
    "ezsql",
    "laravel-db"
  ]
}
```

### Database Connection (Optional)

```json
{
  "sqlens.preview.enabled": false,
  "sqlens.schema.driver": "mysql",
  "sqlens.schema.host": "127.0.0.1",
  "sqlens.schema.port": 3306,
  "sqlens.schema.database": "your_database",
  "sqlens.schema.user": "readonly_user"
}
```

### Security Settings

```json
{
  "sqlens.preview.rowLimit": 5,
  "sqlens.preview.timeoutMs": 2000,
  "sqlens.preview.allowNonSelect": false
}
```

## Security & Privacy

- **Default Mode**: Completely offline static analysis only
- **Optional Features**: Database connections are opt-in only
- **Safe Execution**: Only SELECT queries allowed, with row limits and timeouts
- **No Data Transmission**: All analysis happens locally
- **Read-Only Access**: Database connections use read-only credentials

## Usage Examples

### ezSQL Development

```php
// ✅ Safe - using escape method
$search_term = $db->escape($_GET['search']);
$results = $db->get_results("SELECT id, name FROM users WHERE name LIKE '%{$search_term}%'");

// ✅ Safe - no user input
$active_users = $db->get_row("SELECT COUNT(*) FROM users WHERE active = 1");

// ⚠️ Warning - potential SQL injection
$risky_query = $db->get_results("SELECT * FROM users WHERE email = '" . $_POST['email'] . "'");

// ⚠️ Warning - SELECT * usage
$all_data = $db->get_results("SELECT * FROM large_table");

// ✅ Best Practice - specific columns with escaping
$safe_search = $db->escape($user_input);
$optimized = $db->get_results("SELECT id, name, email FROM users WHERE status = '{$safe_search}'");
```

### WordPress Development

```php
// ✅ Safe - using prepared statements
$results = $wpdb->get_results($wpdb->prepare(
    "SELECT * FROM posts WHERE post_status = %s",
    $status
));

// ⚠️ Warning - potential SQL injection
$results = $wpdb->get_results(
    "SELECT * FROM posts WHERE post_status = '" . $_GET['status'] . "'"
);
```

### Laravel Development

```php
// ✅ Safe - using parameter binding
$users = DB::select('SELECT * FROM users WHERE active = ?', [1]);

// ⚠️ Warning - SELECT * usage
$users = DB::select('SELECT * FROM users');
```

### PDO Development

```php
// ✅ Safe - prepared statement
$stmt = $pdo->prepare('SELECT name FROM users WHERE id = ?');
$stmt->execute([$id]);

// ❌ Error - direct concatenation
$result = $pdo->query("SELECT * FROM users WHERE name = " . $_POST['name']);
```

## Commands

- `SQLens: Preview Query` - Preview query results (max 5 rows)
- `SQLens: Explain Query` - Show execution plan
- `SQLens: Copy Query` - Copy SQL to clipboard
- `SQLens: Refresh Queries` - Refresh query list

## Development

### Prerequisites

- Node.js 20+
- VS Code 1.103+

### Building from Source

```bash
git clone https://github.com/aliyilmazco/sqlens.git
cd sqlens
npm install
npm run compile
```

### Running Tests

```bash
npm run test
```

### Debugging

1. Open in VS Code
2. Press F5 to launch Extension Development Host
3. Open a PHP file to test the extension

## Known Issues

- Complex Eloquent ORM queries may not be fully analyzed
- Taint analysis is basic and may produce false positives/negatives
- EXPLAIN plans require database connection configuration

## Roadmap

- [ ] Enhanced Eloquent ORM support
- [ ] PostgreSQL EXPLAIN plan visualization
- [ ] Advanced taint analysis with data flow tracking
- [ ] Quick fix suggestions (e.g., SELECT \* → specific columns)
- [ ] CI/CD integration for pull request analysis
- [ ] Query performance benchmarking

## License

This project is licensed under the MIT License.

## Acknowledgments

- [php-parser](https://github.com/glayzzle/php-parser) for PHP AST parsing
- [mysql2](https://github.com/sidorares/node-mysql2) for MySQL connectivity
- VS Code team for the excellent extension API
