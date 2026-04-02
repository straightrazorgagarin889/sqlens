import { SQLCall } from "../phpAst";
import { AntiPattern, RuleChecker } from "./ruleTypes";

export class BestPracticeRuleChecker implements RuleChecker {
  category = "best-practice" as const;

  private static readonly NESTED_SELECT_RE = /\(\s*SELECT\b/gi;
  private static readonly HARDCODED_CRED_RE = /\b(password|passwd|pwd|secret|api_key|apikey|token|auth_token)\s*=\s*'[^']+'/i;
  private static readonly PLAINTEXT_PASS_RE = /WHERE\s+.*?\bpassword\s*=\s*/i;
  private static readonly LARGE_OFFSET_BP_RE = /OFFSET\s+(\d+)/i;
  private static readonly SELECT_STAR_SUBQUERY_RE = /\(\s*SELECT\s+\*/i;
  private static readonly FOR_UPDATE_RE = /\bFOR\s+UPDATE\b/i;
  private static readonly LOCK_SHARE_RE = /\bLOCK\s+IN\s+SHARE\s+MODE\b/i;

  check(sqlCall: SQLCall): AntiPattern[] {
    const patterns: AntiPattern[] = [];

    patterns.push(...this.checkSuggestCTE(sqlCall));
    patterns.push(...this.checkSuggestPreparedStmt(sqlCall));
    patterns.push(...this.checkHardcodedCredentials(sqlCall));
    patterns.push(...this.checkPlaintextPassword(sqlCall));
    patterns.push(...this.checkSuggestKeysetPagination(sqlCall));
    patterns.push(...this.checkSuggestExplicitColumns(sqlCall));
    patterns.push(...this.checkSelectForUpdateNoTx(sqlCall));

    // ezSQL specific
    if (sqlCall.framework === "ezsql") {
      patterns.push(...this.checkEzSQLErrorSuppression(sqlCall));
      patterns.push(...this.checkEzSQLDeprecatedMethods(sqlCall));
    }

    return patterns;
  }

  private checkSuggestCTE(sqlCall: SQLCall): AntiPattern[] {
    const matches = sqlCall.sql.match(BestPracticeRuleChecker.NESTED_SELECT_RE);
    if (!matches || matches.length < 2) { return []; }
    return [{
      type: "SUGGEST_CTE",
      category: "best-practice",
      severity: "info",
      message: `Deeply nested subqueries (${matches.length} levels). Consider using Common Table Expressions (CTEs) for readability.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Rewrite with WITH ... AS (...) CTE syntax for clearer query structure",
    }];
  }

  private checkSuggestPreparedStmt(sqlCall: SQLCall): AntiPattern[] {
    if (sqlCall.hasBinding) { return []; }
    if (sqlCall.method === "prepare" || sqlCall.method === "escape") { return []; }
    if (sqlCall.isSafe && sqlCall.variables.filter(v => v !== "$this" && v !== "$self").length === 0) { return []; }

    return [{
      type: "SUGGEST_PREPARED_STMT",
      category: "best-practice",
      severity: "info",
      message: "This query does not use prepared statements. Prepared statements improve security and can improve performance.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use prepared statements with parameter binding",
    }];
  }

  private checkHardcodedCredentials(sqlCall: SQLCall): AntiPattern[] {
    if (!BestPracticeRuleChecker.HARDCODED_CRED_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "HARDCODED_CREDENTIALS",
      category: "security",
      severity: "error",
      message: "Hardcoded credential detected in SQL query. This is a security risk if the code is committed to version control.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use environment variables or a secrets manager for credentials",
    }];
  }

  private checkPlaintextPassword(sqlCall: SQLCall): AntiPattern[] {
    if (!BestPracticeRuleChecker.PLAINTEXT_PASS_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "PLAINTEXT_PASSWORD",
      category: "security",
      severity: "warning",
      message: "Direct password comparison in SQL query suggests plaintext password storage. Use password_hash() and password_verify().",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Hash passwords with password_hash(). Verify with password_verify() in PHP, not in SQL",
    }];
  }

  private checkEzSQLErrorSuppression(sqlCall: SQLCall): AntiPattern[] {
    if (sqlCall.method !== "hide_errors") { return []; }
    return [{
      type: "EZSQL_ERROR_SUPPRESSION",
      category: "best-practice",
      severity: "warning",
      message: "hide_errors() suppresses database errors. This can mask important issues.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use proper error handling instead of suppressing errors",
    }];
  }

  private checkEzSQLDeprecatedMethods(sqlCall: SQLCall): AntiPattern[] {
    const patterns: AntiPattern[] = [];

    if (["debug", "vardump"].includes(sqlCall.method)) {
      patterns.push({
        type: "EZSQL_DEPRECATED_METHOD",
        category: "best-practice",
        severity: "warning",
        message: `${sqlCall.method}() should not be used in production code`,
        line: sqlCall.line,
        column: sqlCall.column,
        suggestion: "Remove debug methods from production code",
      });
    }

    if (/\bmysql_(query|db_query|unbuffered_query|escape_string|connect|close|select_db|fetch_|result|num_rows)\b/.test(sqlCall.sql)) {
      patterns.push({
        type: "EZSQL_DEPRECATED_METHOD",
        category: "best-practice",
        severity: "error",
        message: "Deprecated mysql_* functions detected. Use mysqli or PDO instead.",
        line: sqlCall.line,
        column: sqlCall.column,
        suggestion: "Update to use mysqli_* functions or PDO with ezSQL",
      });
    }

    return patterns;
  }

  private checkSuggestKeysetPagination(sqlCall: SQLCall): AntiPattern[] {
    const match = sqlCall.sql.match(BestPracticeRuleChecker.LARGE_OFFSET_BP_RE);
    if (!match) { return []; }

    const offset = parseInt(match[1], 10);
    if (offset < 100) { return []; }

    return [{
      type: "SUGGEST_KEYSET_PAGINATION",
      category: "best-practice",
      severity: "info",
      message: `OFFSET ${offset} pagination degrades with larger values. Keyset pagination provides consistent performance.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use WHERE id > :last_seen_id ORDER BY id LIMIT n instead of OFFSET",
    }];
  }

  private checkSuggestExplicitColumns(sqlCall: SQLCall): AntiPattern[] {
    if (!BestPracticeRuleChecker.SELECT_STAR_SUBQUERY_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "SUGGEST_EXPLICIT_COLUMNS",
      category: "best-practice",
      severity: "info",
      message: "SELECT * in subquery fetches all columns unnecessarily. Specify only needed columns.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Replace * with specific column names in subqueries",
    }];
  }

  private checkSelectForUpdateNoTx(sqlCall: SQLCall): AntiPattern[] {
    const hasLock = BestPracticeRuleChecker.FOR_UPDATE_RE.test(sqlCall.sql)
      || BestPracticeRuleChecker.LOCK_SHARE_RE.test(sqlCall.sql);
    if (!hasLock) { return []; }

    const ctx = sqlCall.surroundingCode || "";
    const hasTransaction = /\b(beginTransaction|begin|START\s+TRANSACTION)\b/i.test(ctx);

    if (!hasTransaction) {
      return [{
        type: "SELECT_FOR_UPDATE_NO_TX",
        category: "best-practice",
        severity: "warning",
        message: "SELECT ... FOR UPDATE without an explicit transaction. Lock is released immediately after auto-commit.",
        line: sqlCall.line,
        column: sqlCall.column,
        suggestion: "Wrap in a transaction: $pdo->beginTransaction() ... $pdo->commit()",
      }];
    }
    return [];
  }
}
