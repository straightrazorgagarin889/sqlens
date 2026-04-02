import { SQLCall } from "../phpAst";
import { AntiPattern, RuleChecker } from "./ruleTypes";

export class CorrectnessRuleChecker implements RuleChecker {
  category = "correctness" as const;

  private static readonly NULL_CMP_RE = /(?:=|!=|<>)\s*NULL\b/i;
  private static readonly BETWEEN_DATE_RE = /BETWEEN\s+['"][^'"]*\d{4}-\d{2}-\d{2}/i;
  // Matches COUNT(column) but NOT COUNT(*) or COUNT(DISTINCT ...)
  private static readonly COUNT_COL_RE = /\bCOUNT\s*\(\s*(?!\*\s*\))(?!DISTINCT\b)[\w.]+\s*\)/i;
  private static readonly HAVING_RE = /\bHAVING\b/i;
  private static readonly GROUP_BY_RE = /\bGROUP\s+BY\b/i;
  private static readonly LIMIT_RE = /\bLIMIT\b/i;
  private static readonly ORDER_BY_RE = /\bORDER\s+BY\b/i;
  private static readonly NOT_IN_RE = /\bNOT\s+IN\s*\(/i;
  private static readonly DISTINCT_RE = /\bSELECT\s+DISTINCT\b/i;
  private static readonly CASE_RE = /\bCASE\b/i;
  private static readonly ELSE_RE = /\bELSE\b/i;
  private static readonly END_RE = /\bEND\b/i;
  private static readonly JOIN_RE = /\bJOIN\b/i;
  private static readonly MULTI_TABLE_RE = /\bFROM\s+\w+\s*(,|\bJOIN\b)/i;

  check(sqlCall: SQLCall): AntiPattern[] {
    const patterns: AntiPattern[] = [];

    patterns.push(...this.checkNullComparison(sqlCall));
    patterns.push(...this.checkBetweenDatetime(sqlCall));
    patterns.push(...this.checkCountColumnSemantics(sqlCall));
    patterns.push(...this.checkHavingNoGroupBy(sqlCall));
    patterns.push(...this.checkLimitNoOrderBy(sqlCall));
    patterns.push(...this.checkNotInNullable(sqlCall));
    patterns.push(...this.checkRedundantDistinct(sqlCall));
    patterns.push(...this.checkAmbiguousColumn(sqlCall));
    patterns.push(...this.checkCaseNoElse(sqlCall));
    patterns.push(...this.checkGroupByNonAggregated(sqlCall));
    patterns.push(...this.checkMixedAndOrPrecedence(sqlCall));

    return patterns;
  }

  private checkNullComparison(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.NULL_CMP_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "NULL_COMPARISON",
      category: "correctness",
      severity: "error",
      message: "Use IS NULL or IS NOT NULL instead of = NULL or != NULL. Equality operators always return NULL when compared with NULL.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Replace = NULL with IS NULL, != NULL / <> NULL with IS NOT NULL",
    }];
  }

  private checkBetweenDatetime(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.BETWEEN_DATE_RE.test(sqlCall.sql)) { return []; }

    // Check if it's a date-only comparison (no time component)
    const match = sqlCall.sql.match(/BETWEEN\s+['"](\d{4}-\d{2}-\d{2})['"]\s+AND\s+['"](\d{4}-\d{2}-\d{2})['"]/i);
    if (!match) { return []; }

    return [{
      type: "BETWEEN_DATETIME",
      category: "correctness",
      severity: "info",
      message: "BETWEEN with date values may miss records. '2024-01-31' means '2024-01-31 00:00:00', excluding the rest of that day.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use >= '2024-01-01' AND < '2024-02-01' for inclusive date ranges",
    }];
  }

  private checkCountColumnSemantics(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.COUNT_COL_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "COUNT_COLUMN_SEMANTICS",
      category: "correctness",
      severity: "info",
      message: "COUNT(column) silently excludes NULL values. If you want to count all rows, use COUNT(*).",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use COUNT(*) for total row count, COUNT(column) only when NULL exclusion is intentional",
    }];
  }

  private checkHavingNoGroupBy(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.HAVING_RE.test(sqlCall.sql)) { return []; }
    if (CorrectnessRuleChecker.GROUP_BY_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "HAVING_NO_GROUP_BY",
      category: "correctness",
      severity: "warning",
      message: "HAVING without GROUP BY treats the entire result set as a single group. Use WHERE instead.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Replace HAVING with WHERE when there is no GROUP BY clause",
    }];
  }

  private checkLimitNoOrderBy(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.LIMIT_RE.test(sqlCall.sql)) { return []; }
    if (CorrectnessRuleChecker.ORDER_BY_RE.test(sqlCall.sql)) { return []; }
    // Skip INSERT/UPDATE/DELETE - LIMIT without ORDER BY is fine there
    if (/^\s*(INSERT|UPDATE|DELETE)\b/i.test(sqlCall.sql)) { return []; }
    return [{
      type: "LIMIT_NO_ORDER_BY",
      category: "correctness",
      severity: "info",
      message: "LIMIT without ORDER BY returns non-deterministic results. Different executions may return different rows.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Add ORDER BY to ensure consistent, predictable results",
    }];
  }

  private checkNotInNullable(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.NOT_IN_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "NOT_IN_NULLABLE",
      category: "correctness",
      severity: "info",
      message: "NOT IN can return unexpected empty results if the subquery/list contains NULL values.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use NOT EXISTS instead, or ensure the subquery cannot return NULLs",
    }];
  }

  private checkRedundantDistinct(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.DISTINCT_RE.test(sqlCall.sql)) { return []; }
    if (!CorrectnessRuleChecker.GROUP_BY_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "REDUNDANT_DISTINCT",
      category: "correctness",
      severity: "info",
      message: "DISTINCT with GROUP BY is redundant. GROUP BY already produces unique groups.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Remove DISTINCT when GROUP BY already ensures uniqueness",
    }];
  }

  private checkAmbiguousColumn(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.MULTI_TABLE_RE.test(sqlCall.sql)) { return []; }

    // Check for unqualified columns in WHERE/SELECT of multi-table queries
    // Look for common column names without table prefix
    const commonCols = /\b(WHERE|AND|OR|ON|SET)\s+(?![\w.]*\.)(id|name|status|type|created_at|updated_at|email|user_id)\s*[=<>!]/i;
    if (!commonCols.test(sqlCall.sql)) { return []; }

    return [{
      type: "AMBIGUOUS_COLUMN",
      category: "correctness",
      severity: "info",
      message: "Unqualified column reference in multi-table query may be ambiguous.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Prefix columns with table name or alias: table.column",
    }];
  }

  private checkCaseNoElse(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.CASE_RE.test(sqlCall.sql)) { return []; }
    if (!CorrectnessRuleChecker.END_RE.test(sqlCall.sql)) { return []; }
    if (CorrectnessRuleChecker.ELSE_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "CASE_NO_ELSE",
      category: "correctness",
      severity: "info",
      message: "CASE expression without ELSE clause returns NULL for unmatched conditions.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Add an ELSE clause to handle unmatched conditions explicitly",
    }];
  }

  private checkGroupByNonAggregated(sqlCall: SQLCall): AntiPattern[] {
    if (!CorrectnessRuleChecker.GROUP_BY_RE.test(sqlCall.sql)) { return []; }

    const selectMatch = sqlCall.sql.match(/SELECT\s+(.*?)\s+FROM/is);
    const groupByMatch = sqlCall.sql.match(/GROUP\s+BY\s+([\w.,\s`]+?)(?:\s+HAVING|\s+ORDER|\s+LIMIT|\s*$)/i);
    if (!selectMatch || !groupByMatch) { return []; }

    const aggregateFunctions = /\b(COUNT|SUM|AVG|MIN|MAX|GROUP_CONCAT)\s*\(/i;
    const selectCols = selectMatch[1].split(",").map(c => c.trim());
    const groupByCols = groupByMatch[1].split(",").map(c => c.trim().toLowerCase().replace(/`/g, ""));

    const nonAggregated = selectCols.filter(col => {
      if (aggregateFunctions.test(col) || col === "*") { return false; }
      const cleanCol = col.replace(/\s+AS\s+\w+/i, "").trim().toLowerCase().replace(/`/g, "");
      const colName = cleanCol.includes(".") ? cleanCol.split(".").pop()! : cleanCol;
      return !groupByCols.some(gc => {
        const gcName = gc.includes(".") ? gc.split(".").pop()! : gc;
        return gcName === colName || gc === cleanCol;
      });
    });

    if (nonAggregated.length === 0) { return []; }

    return [{
      type: "GROUP_BY_NON_AGGREGATED",
      category: "correctness",
      severity: "warning",
      message: `Non-aggregated column(s) in SELECT not in GROUP BY. Results may be non-deterministic.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Add all non-aggregated columns to GROUP BY or wrap them in an aggregate function",
    }];
  }

  private checkMixedAndOrPrecedence(sqlCall: SQLCall): AntiPattern[] {
    const whereMatch = sqlCall.sql.match(/WHERE\s+(.*)/is);
    if (!whereMatch) { return []; }

    const whereClause = whereMatch[1];
    const hasAnd = /\bAND\b/i.test(whereClause);
    const hasOr = /\bOR\b/i.test(whereClause);
    const hasParens = /\(/.test(whereClause);

    if (hasAnd && hasOr && !hasParens) {
      return [{
        type: "MIXED_AND_OR_PRECEDENCE",
        category: "correctness",
        severity: "warning",
        message: "Mixed AND/OR without parentheses. AND has higher precedence than OR, which may cause unexpected results.",
        line: sqlCall.line,
        column: sqlCall.column,
        suggestion: "Add parentheses to clarify precedence: WHERE (a OR b) AND c",
      }];
    }
    return [];
  }
}
