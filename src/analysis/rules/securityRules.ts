import { SQLCall } from "../phpAst";
import { AntiPattern, RuleChecker } from "./ruleTypes";

export class SecurityRuleChecker implements RuleChecker {
  category = "security" as const;

  private static readonly DEPRECATED_MYSQL_RE = /\bmysql_(query|db_query|unbuffered_query|escape_string)\s*\(/i;
  private static readonly STACKED_QUERIES_RE = /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE)\b/i;
  private static readonly FILE_OPERATION_RE = /\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b/i;
  private static readonly DDL_IN_APP_RE = /\b(GRANT\s|REVOKE\s)/i;
  private static readonly SPRINTF_TAINT_RE = /sprintf\s*\(/i;
  private static readonly TIMING_ATTACK_RE = /\b(SLEEP|BENCHMARK)\s*\(/i;
  private static readonly INFO_SCHEMA_RE = /\binformation_schema\b/i;

  private static readonly HIGH_RISK_TAINT_RE = /\$_(GET|POST|REQUEST)\b/;
  private static readonly MEDIUM_RISK_TAINT_RE = /\$_(COOKIE|SERVER)\b/;
  private static readonly FILES_TAINT_RE = /\$_FILES\b/;
  private static readonly ENV_TAINT_RE = /\$_(ENV)\s*\[|getenv\s*\(|getallheaders\s*\(/i;
  private static readonly INPUT_STREAM_RE = /file_get_contents\s*\(\s*['"]php:\/\/input['"]/i;
  private static readonly EXTRACT_RE = /\b(extract|parse_str)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/;
  private static readonly ARGV_RE = /\$argv\b/;

  check(sqlCall: SQLCall): AntiPattern[] {
    const patterns: AntiPattern[] = [];

    patterns.push(...this.checkSQLInjection(sqlCall));
    patterns.push(...this.checkSprintfTaint(sqlCall));
    patterns.push(...this.checkDeprecatedMysql(sqlCall));
    patterns.push(...this.checkWpdbNoPrepare(sqlCall));
    patterns.push(...this.checkLaravelRawNoBinding(sqlCall));
    patterns.push(...this.checkStackedQueries(sqlCall));
    patterns.push(...this.checkFileOperations(sqlCall));
    patterns.push(...this.checkDDLInApp(sqlCall));
    patterns.push(...this.checkTimingAttack(sqlCall));
    patterns.push(...this.checkInfoSchemaAccess(sqlCall));

    // ezSQL specific
    if (sqlCall.framework === "ezsql") {
      patterns.push(...this.checkEzSQLEscaping(sqlCall));
    }

    return patterns;
  }

  private checkSQLInjection(sqlCall: SQLCall): AntiPattern[] {
    if (sqlCall.isSafe) { return []; }

    const sql = sqlCall.sql;
    let severity: "error" | "warning" | "info" = "info";

    if (SecurityRuleChecker.HIGH_RISK_TAINT_RE.test(sql)) {
      severity = "error";
    } else if (SecurityRuleChecker.MEDIUM_RISK_TAINT_RE.test(sql)) {
      severity = "warning";
    } else if (SecurityRuleChecker.FILES_TAINT_RE.test(sql)) {
      severity = "error";
    } else if (SecurityRuleChecker.ENV_TAINT_RE.test(sql)) {
      severity = "warning";
    } else if (SecurityRuleChecker.INPUT_STREAM_RE.test(sql)) {
      severity = "error";
    } else if (SecurityRuleChecker.ARGV_RE.test(sql)) {
      severity = "warning";
    }

    // Also check surrounding code for taint patterns
    const ctx = sqlCall.surroundingCode;
    if (ctx) {
      if (SecurityRuleChecker.EXTRACT_RE.test(ctx)) {
        severity = "error";
      }
      if (SecurityRuleChecker.INPUT_STREAM_RE.test(ctx)) {
        severity = severity === "info" ? "error" : severity;
      }
    }

    return [{
      type: "SQL_INJECTION",
      category: "security",
      severity,
      message: "Potential SQL injection vulnerability detected. Use prepared statements.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use prepared statements with parameter binding",
    }];
  }

  private checkSprintfTaint(sqlCall: SQLCall): AntiPattern[] {
    if (sqlCall.hasBinding) { return []; }

    // Check both the SQL itself and surrounding code for sprintf with %s
    const hasSprintf = sqlCall.usesSprintfInterpolation
      || SecurityRuleChecker.SPRINTF_TAINT_RE.test(sqlCall.surroundingCode || "");

    if (!hasSprintf) { return []; }

    // Check if sprintf format string contains %s (string interpolation, not %d which is safer)
    const ctx = (sqlCall.surroundingCode || "") + " " + sqlCall.sql;
    if (!ctx.includes("%s")) { return []; }

    return [{
      type: "SPRINTF_TAINT",
      category: "security",
      severity: "error",
      message: "sprintf() with %s in SQL query is vulnerable to injection. Use prepared statements instead.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Replace sprintf() with prepared statements and parameter binding",
    }];
  }

  private checkDeprecatedMysql(sqlCall: SQLCall): AntiPattern[] {
    // Check both the SQL context and surrounding PHP code
    const haystack = (sqlCall.surroundingCode || "") + " " + (sqlCall.sql || "");
    if (!SecurityRuleChecker.DEPRECATED_MYSQL_RE.test(haystack)) {
      return [];
    }
    return [{
      type: "DEPRECATED_MYSQL",
      category: "security",
      severity: "error",
      message: "Deprecated mysql_* functions detected. These were removed in PHP 7.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Migrate to PDO or MySQLi with prepared statements",
    }];
  }

  private checkWpdbNoPrepare(sqlCall: SQLCall): AntiPattern[] {
    if (sqlCall.framework !== "wordpress") { return []; }
    if (sqlCall.method === "prepare") { return []; }
    if (sqlCall.hasBinding) { return []; }

    // Check if the SQL was wrapped in $wpdb->prepare()
    if (sqlCall.surroundingCode && /->prepare\s*\(/.test(sqlCall.surroundingCode)) { return []; }

    return [{
      type: "WPDB_NO_PREPARE",
      category: "security",
      severity: "error",
      message: `WordPress $wpdb->${sqlCall.method}() called without $wpdb->prepare(). Vulnerable to SQL injection.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Wrap the query with $wpdb->prepare() using %s/%d placeholders",
    }];
  }

  private checkLaravelRawNoBinding(sqlCall: SQLCall): AntiPattern[] {
    if (sqlCall.framework !== "laravel-db") { return []; }

    const rawMethods = ["raw", "whereRaw", "selectRaw", "orderByRaw", "groupByRaw", "havingRaw", "unprepared"];
    if (!rawMethods.includes(sqlCall.method)) { return []; }
    if (sqlCall.hasBinding) { return []; }

    return [{
      type: "LARAVEL_RAW_NO_BINDING",
      category: "security",
      severity: "error",
      message: `Laravel ${sqlCall.method}() called without bindings parameter. Vulnerable to SQL injection.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: `Pass bindings as the second parameter: ${sqlCall.method}('...', [\$param])`,
    }];
  }

  private checkStackedQueries(sqlCall: SQLCall): AntiPattern[] {
    if (!SecurityRuleChecker.STACKED_QUERIES_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "STACKED_QUERIES",
      category: "security",
      severity: "error",
      message: "Multiple SQL statements in a single query string (stacked queries). This is a SQL injection risk.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Execute each SQL statement separately",
    }];
  }

  private checkFileOperations(sqlCall: SQLCall): AntiPattern[] {
    if (!SecurityRuleChecker.FILE_OPERATION_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "FILE_OPERATION",
      category: "security",
      severity: "error",
      message: "SQL file operation detected (LOAD_FILE/INTO OUTFILE/DUMPFILE). This can lead to data exfiltration.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Avoid file operations in SQL. Use application-level file handling",
    }];
  }

  private checkDDLInApp(sqlCall: SQLCall): AntiPattern[] {
    if (!SecurityRuleChecker.DDL_IN_APP_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "DDL_IN_APP",
      category: "security",
      severity: "error",
      message: "GRANT/REVOKE statement in application code. Privilege management should not be in application logic.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Manage database privileges through migration scripts or DBA tools",
    }];
  }

  private checkTimingAttack(sqlCall: SQLCall): AntiPattern[] {
    if (!SecurityRuleChecker.TIMING_ATTACK_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "TIMING_ATTACK",
      category: "security",
      severity: "error",
      message: "SLEEP()/BENCHMARK() detected in SQL. These are commonly used in timing-based SQL injection attacks.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Remove SLEEP/BENCHMARK calls. If used for testing, use application-level delays instead",
    }];
  }

  private checkInfoSchemaAccess(sqlCall: SQLCall): AntiPattern[] {
    if (!SecurityRuleChecker.INFO_SCHEMA_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "INFO_SCHEMA_ACCESS",
      category: "security",
      severity: "warning",
      message: "Query accesses information_schema. This exposes database structure metadata.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Avoid querying information_schema in application code. Use migrations or admin tools",
    }];
  }

  private checkEzSQLEscaping(sqlCall: SQLCall): AntiPattern[] {
    const hasUserInput = /\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/.test(sqlCall.sql);
    // Check for escaping: look for ->escape(, addslashes(, etc. - require word boundary or -> before "escape"
    const hasEscaping = /(?:->escape\s*\(|(?:^|\W)addslashes\s*\(|\bmysql_real_escape_string\s*\(|\bmysqli_real_escape_string\s*\()/i.test(
      sqlCall.sql + " " + (sqlCall.surroundingCode || "")
    );

    if (hasUserInput && !hasEscaping && !sqlCall.hasBinding) {
      return [{
        type: "EZSQL_NO_ESCAPE",
        category: "security",
        severity: "error",
        message: "User input detected without proper escaping in ezSQL query",
        line: sqlCall.line,
        column: sqlCall.column,
        suggestion: "Use $db->escape() method or prepared statements to escape user input",
      }];
    }
    return [];
  }
}
