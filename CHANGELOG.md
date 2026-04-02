# CHANGELOG

All notable changes to the "SQLens" extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1] - 2025-09-03

### Added

- Initial release of SQLens
- PHP AST parsing for SQL query detection
- Support for multiple PHP frameworks:
  - WordPress ($wpdb methods)
  - Laravel (DB facade)
  - PDO (query, prepare, exec)
  - MySQLi (query, prepare)
  - ezSQL (get_results, query)
- Security analysis features:
  - SQL injection vulnerability detection
  - Taint analysis for unsafe user input
  - Parameter binding validation
- Performance analysis:
  - SELECT \* usage warnings
  - NULL comparison anti-patterns
  - OR explosion detection
  - Index usage recommendations
- VS Code integration:
  - Hover provider with query analysis
  - CodeLens with Preview/Explain/Copy actions
  - Diagnostics with severity levels
  - Tree view for workspace queries
  - Webview for EXPLAIN plan visualization
- Database connectivity (optional):
  - MySQL support with mysql2
  - PostgreSQL support with pg
  - Safe query preview (SELECT only, limited rows)
  - EXPLAIN plan execution
  - Schema discovery and caching
- Comprehensive configuration options
- Security-first approach with read-only defaults

### Security

- All database operations are opt-in and read-only by default
- Query preview limited to SELECT statements only
- Row limits and timeouts for safety
- No external data transmission
- Local-only analysis and storage
