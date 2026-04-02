import { SQLCall } from "../phpAst";
import { AntiPattern, RuleChecker } from "./ruleTypes";

export class PerformanceRuleChecker implements RuleChecker {
  category = "performance" as const;

  private static readonly SELECT_STAR_RE = /SELECT\s+\*/i;
  private static readonly ORDER_BY_RAND_RE = /ORDER\s+BY\s+RAND\s*\(\)/i;
  private static readonly LEADING_WILDCARD_RE = /LIKE\s+['"]%/i;
  private static readonly LARGE_OFFSET_RE = /OFFSET\s+(\d+)/i;
  private static readonly UNION_WITHOUT_ALL_RE = /\bUNION\b(?!\s+ALL)/i;
  private static readonly COUNT_EXISTS_RE = /SELECT\s+COUNT\s*\(\s*\*?\s*\)/i;
  private static readonly OLD_STYLE_JOIN_RE = /\bFROM\s+\w+(?:\s+(?:AS\s+)?\w+)?\s*,\s*\w+/i;
  private static readonly OR_RE = /\sOR\s/gi;
  // Correlated subquery: a subquery that references a table alias from the outer query
  private static readonly SUBQUERY_RE = /\(\s*SELECT\b/i;
  private static readonly NOW_RE = /\b(NOW\s*\(\)|CURRENT_TIMESTAMP)\b/i;
  private static readonly RAND_RE = /\bRAND\s*\(\)/i;

  // Functions applied to columns in WHERE clause - matches "WHERE ... FUNC(col" or "AND FUNC(col"
  // Excludes aggregate functions (COUNT, SUM, AVG, MIN, MAX) which are used in HAVING, not WHERE on columns
  private static readonly FUNCTION_ON_COL_NAMES = [
    "DATE", "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND",
    "LOWER", "UPPER", "SUBSTRING", "SUBSTR", "TRIM", "LTRIM", "RTRIM",
    "CAST", "CONVERT", "COALESCE", "IFNULL", "ISNULL", "NVL",
    "LENGTH", "CHAR_LENGTH", "CONCAT",
  ];
  private static readonly FUNCTION_ON_COL_RE = new RegExp(
    `\\b(WHERE|AND|OR)\\s+(?:[\\w.]+\\s*(?:=|<|>|!=|<>|<=|>=|LIKE|IN)\\s+.*?)?\\b(${PerformanceRuleChecker.FUNCTION_ON_COL_NAMES.join("|")})\\s*\\(\\s*[a-zA-Z_]`,
    "i"
  );

  // Cartesian: FROM with multiple tables and no JOIN or WHERE linking them
  private static readonly MULTI_TABLE_FROM_RE = /\bFROM\s+\w+(?:\s+(?:AS\s+)?\w+)?\s*,\s*\w+/i;
  private static readonly JOIN_RE = /\bJOIN\b/i;

  check(sqlCall: SQLCall): AntiPattern[] {
    const patterns: AntiPattern[] = [];

    patterns.push(...this.checkSelectStar(sqlCall));
    patterns.push(...this.checkOrderByRand(sqlCall));
    patterns.push(...this.checkLeadingWildcard(sqlCall));
    patterns.push(...this.checkFunctionOnColumn(sqlCall));
    patterns.push(...this.checkLargeOffset(sqlCall));
    patterns.push(...this.checkNPlusOne(sqlCall));
    patterns.push(...this.checkCartesianJoin(sqlCall));
    patterns.push(...this.checkUnionVsUnionAll(sqlCall));
    patterns.push(...this.checkCountForExists(sqlCall));
    patterns.push(...this.checkOldStyleJoin(sqlCall));
    patterns.push(...this.checkOrExplosion(sqlCall));
    patterns.push(...this.checkCorrelatedSubquery(sqlCall));

    // ezSQL cache bypass
    if (sqlCall.framework === "ezsql") {
      patterns.push(...this.checkEzSQLCacheBypass(sqlCall));
    }

    return patterns;
  }

  private checkSelectStar(sqlCall: SQLCall): AntiPattern[] {
    if (!PerformanceRuleChecker.SELECT_STAR_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "SELECT_STAR",
      category: "performance",
      severity: "warning",
      message: "Avoid SELECT * in production code. Specify column names explicitly for better performance and clarity.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Replace * with specific column names",
    }];
  }

  private checkOrderByRand(sqlCall: SQLCall): AntiPattern[] {
    if (!PerformanceRuleChecker.ORDER_BY_RAND_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "ORDER_BY_RAND",
      category: "performance",
      severity: "warning",
      message: "ORDER BY RAND() forces a full table scan and sort. Very slow on large tables.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use application-level randomization or a random ID approach",
    }];
  }

  private checkLeadingWildcard(sqlCall: SQLCall): AntiPattern[] {
    if (!PerformanceRuleChecker.LEADING_WILDCARD_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "LEADING_WILDCARD",
      category: "performance",
      severity: "warning",
      message: "LIKE pattern with leading wildcard (%) prevents index usage. Causes full table scan.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Consider full-text search or reverse index for prefix-independent searches",
    }];
  }

  private checkFunctionOnColumn(sqlCall: SQLCall): AntiPattern[] {
    if (!PerformanceRuleChecker.FUNCTION_ON_COL_RE.test(sqlCall.sql)) { return []; }

    const match = sqlCall.sql.match(PerformanceRuleChecker.FUNCTION_ON_COL_RE);
    const funcName = match ? match[2].toUpperCase() : "FUNCTION";

    return [{
      type: "FUNCTION_ON_COLUMN",
      category: "performance",
      severity: "warning",
      message: `${funcName}() applied to a column in WHERE clause prevents index usage.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: `Restructure the query to avoid applying ${funcName}() on the column. Use range conditions instead`,
    }];
  }

  private checkLargeOffset(sqlCall: SQLCall): AntiPattern[] {
    const match = sqlCall.sql.match(PerformanceRuleChecker.LARGE_OFFSET_RE);
    if (!match) { return []; }

    const offset = parseInt(match[1], 10);
    if (offset < 1000) { return []; }

    return [{
      type: "LARGE_OFFSET",
      category: "performance",
      severity: "warning",
      message: `Large OFFSET (${offset}) forces the database to scan and discard rows. Degrades with table size.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use keyset pagination: WHERE id > :last_seen_id ORDER BY id LIMIT n",
    }];
  }

  private checkNPlusOne(sqlCall: SQLCall): AntiPattern[] {
    if (!sqlCall.enclosingLoop) { return []; }
    return [{
      type: "N_PLUS_ONE",
      category: "performance",
      severity: "warning",
      message: `SQL query inside a ${sqlCall.loopType || "loop"}. This is an N+1 query pattern causing excessive database round-trips.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Batch the query: fetch all needed data in one query before the loop, or use JOINs",
    }];
  }

  private checkCartesianJoin(sqlCall: SQLCall): AntiPattern[] {
    if (!PerformanceRuleChecker.MULTI_TABLE_FROM_RE.test(sqlCall.sql)) { return []; }
    if (PerformanceRuleChecker.JOIN_RE.test(sqlCall.sql)) { return []; }

    // Has multiple tables in FROM with commas and no explicit JOIN
    // Check if WHERE clause links them (old-style join)
    const hasWhere = /\bWHERE\b/i.test(sqlCall.sql);
    if (hasWhere) { return []; } // Old-style join handled by OLD_STYLE_JOIN rule

    return [{
      type: "CARTESIAN_JOIN",
      category: "performance",
      severity: "warning",
      message: "Multiple tables in FROM without JOIN condition creates a Cartesian product (every row x every row).",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Add a JOIN condition or use explicit JOIN syntax",
    }];
  }

  private checkUnionVsUnionAll(sqlCall: SQLCall): AntiPattern[] {
    // Negative lookahead already excludes UNION ALL, no need for second check
    if (!PerformanceRuleChecker.UNION_WITHOUT_ALL_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "UNION_VS_UNION_ALL",
      category: "performance",
      severity: "info",
      message: "UNION removes duplicates (expensive sort). If duplicates are impossible or acceptable, use UNION ALL.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Replace UNION with UNION ALL if duplicate removal is not needed",
    }];
  }

  private checkCountForExists(sqlCall: SQLCall): AntiPattern[] {
    if (!PerformanceRuleChecker.COUNT_EXISTS_RE.test(sqlCall.sql)) { return []; }

    // Check if it's being used for existence check (context clue: > 0, == 0, etc.)
    const ctx = sqlCall.surroundingCode || "";
    if (!(/>\s*0|==\s*0|!=\s*0|===\s*0|!==\s*0/).test(ctx)) { return []; }

    return [{
      type: "COUNT_FOR_EXISTS",
      category: "performance",
      severity: "info",
      message: "Using COUNT(*) for existence check is slower than EXISTS. COUNT scans all matching rows.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use SELECT EXISTS(SELECT 1 FROM ... WHERE ...) or LIMIT 1 instead",
    }];
  }

  private checkOldStyleJoin(sqlCall: SQLCall): AntiPattern[] {
    if (!PerformanceRuleChecker.OLD_STYLE_JOIN_RE.test(sqlCall.sql)) { return []; }
    if (PerformanceRuleChecker.JOIN_RE.test(sqlCall.sql)) { return []; }

    // Only flag if there IS a WHERE clause linking them (otherwise it's CARTESIAN_JOIN)
    if (!/\bWHERE\b/i.test(sqlCall.sql)) { return []; }

    return [{
      type: "OLD_STYLE_JOIN",
      category: "performance",
      severity: "info",
      message: "Old-style comma join syntax (FROM a, b WHERE ...). Harder to read and maintain.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use explicit JOIN syntax: FROM a INNER JOIN b ON a.id = b.a_id",
    }];
  }

  private checkOrExplosion(sqlCall: SQLCall): AntiPattern[] {
    const matches = sqlCall.sql.match(PerformanceRuleChecker.OR_RE);
    if (!matches || matches.length < 3) { return []; }
    return [{
      type: "OR_EXPLOSION",
      category: "performance",
      severity: "warning",
      message: `Too many OR clauses (${matches.length}). Can cause poor query plans and full table scans.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use IN clause or UNION instead of multiple OR conditions",
    }];
  }

  private checkCorrelatedSubquery(sqlCall: SQLCall): AntiPattern[] {
    // Skip expensive check on very long SQL
    if (sqlCall.sql.length > 5000) { return []; }
    if (!PerformanceRuleChecker.SUBQUERY_RE.test(sqlCall.sql)) { return []; }

    // Normalize whitespace for easier matching
    const normalized = sqlCall.sql.replace(/\s+/g, " ");

    // Extract outer table aliases from FROM clause (before subquery)
    const outerAliases: string[] = [];
    const fromMatch = normalized.match(/\bFROM\s+(\w+)(?:\s+(?:AS\s+)?(\w+))?/i);
    if (fromMatch) {
      outerAliases.push(fromMatch[2] || fromMatch[1]);
      if (fromMatch[1]) { outerAliases.push(fromMatch[1]); }
    }
    // Also check JOIN aliases
    const joinMatches = normalized.matchAll(/\bJOIN\s+(\w+)(?:\s+(?:AS\s+)?(\w+))?/gi);
    for (const jm of joinMatches) {
      outerAliases.push(jm[2] || jm[1]);
      if (jm[1]) { outerAliases.push(jm[1]); }
    }

    if (outerAliases.length === 0) { return []; }

    // Check if subquery references any outer alias: (SELECT ... outer_alias.column ...)
    const outerPattern = new RegExp(
      `\\(\\s*SELECT\\b[\\s\\S]*?\\b(${outerAliases.join("|")})\\.\\w+`, "i"
    );
    if (!outerPattern.test(normalized)) { return []; }

    return [{
      type: "CORRELATED_SUBQUERY",
      category: "performance",
      severity: "warning",
      message: "Correlated subquery detected. Executes once per row of the outer query.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Rewrite as a JOIN or use a derived table for better performance",
    }];
  }

  private checkEzSQLCacheBypass(sqlCall: SQLCall): AntiPattern[] {
    const patterns: AntiPattern[] = [];

    if (PerformanceRuleChecker.RAND_RE.test(sqlCall.sql)) {
      patterns.push({
        type: "EZSQL_CACHE_BYPASS",
        category: "performance",
        severity: "warning",
        message: "RAND() in query bypasses ezSQL cache optimization",
        line: sqlCall.line,
        column: sqlCall.column,
        suggestion: "Consider application-level randomization",
      });
    }

    if (PerformanceRuleChecker.NOW_RE.test(sqlCall.sql)) {
      patterns.push({
        type: "EZSQL_CACHE_BYPASS",
        category: "performance",
        severity: "info",
        message: "Time-based functions (NOW/CURRENT_TIMESTAMP) reduce ezSQL cache effectiveness",
        line: sqlCall.line,
        column: sqlCall.column,
        suggestion: "Consider if real-time data is necessary for this query",
      });
    }

    return patterns;
  }
}
