import { SQLCall } from "../phpAst";

// =========================================================================
// Anti-Pattern Categories
// =========================================================================

export type RuleCategory =
  | "security"
  | "safety"
  | "performance"
  | "correctness"
  | "best-practice";

// =========================================================================
// Anti-Pattern Type Literals
// =========================================================================

export type SecurityRuleType =
  | "SQL_INJECTION"
  | "EZSQL_NO_ESCAPE"
  | "SPRINTF_TAINT"
  | "DEPRECATED_MYSQL"
  | "WPDB_NO_PREPARE"
  | "LARAVEL_RAW_NO_BINDING"
  | "STACKED_QUERIES"
  | "FILE_OPERATION"
  | "DDL_IN_APP"
  | "TIMING_ATTACK"
  | "INFO_SCHEMA_ACCESS";

export type SafetyRuleType =
  | "UPDATE_NO_WHERE"
  | "DELETE_NO_WHERE"
  | "DESTRUCTIVE_DDL"
  | "INSERT_NO_COLUMNS"
  | "ERROR_DISCLOSURE"
  | "REPLACE_STATEMENT"
  | "ALTER_DROP_COLUMN";

export type PerformanceRuleType =
  | "SELECT_STAR"
  | "OR_EXPLOSION"
  | "MISSING_INDEX"
  | "EZSQL_CACHE_BYPASS"
  | "ORDER_BY_RAND"
  | "LEADING_WILDCARD"
  | "FUNCTION_ON_COLUMN"
  | "LARGE_OFFSET"
  | "N_PLUS_ONE"
  | "CARTESIAN_JOIN"
  | "UNION_VS_UNION_ALL"
  | "COUNT_FOR_EXISTS"
  | "OLD_STYLE_JOIN"
  | "CORRELATED_SUBQUERY";

export type CorrectnessRuleType =
  | "NULL_COMPARISON"
  | "BETWEEN_DATETIME"
  | "COUNT_COLUMN_SEMANTICS"
  | "HAVING_NO_GROUP_BY"
  | "LIMIT_NO_ORDER_BY"
  | "NOT_IN_NULLABLE"
  | "REDUNDANT_DISTINCT"
  | "AMBIGUOUS_COLUMN"
  | "CASE_NO_ELSE"
  | "GROUP_BY_NON_AGGREGATED"
  | "MIXED_AND_OR_PRECEDENCE";

export type BestPracticeRuleType =
  | "EZSQL_ERROR_SUPPRESSION"
  | "EZSQL_DEPRECATED_METHOD"
  | "SUGGEST_CTE"
  | "SUGGEST_KEYSET_PAGINATION"
  | "SUGGEST_PREPARED_STMT"
  | "HARDCODED_CREDENTIALS"
  | "PLAINTEXT_PASSWORD"
  | "SUGGEST_EXPLICIT_COLUMNS"
  | "OLD_JOIN_SYNTAX"
  | "SELECT_FOR_UPDATE_NO_TX";

export type AntiPatternType =
  | SecurityRuleType
  | SafetyRuleType
  | PerformanceRuleType
  | CorrectnessRuleType
  | BestPracticeRuleType;

// =========================================================================
// Anti-Pattern Interface
// =========================================================================

export interface AntiPattern {
  type: AntiPatternType;
  category: RuleCategory;
  severity: "error" | "warning" | "info";
  message: string;
  line: number;
  column: number;
  suggestion?: string;
}

// =========================================================================
// Rule Checker Interface
// =========================================================================

export interface RuleChecker {
  category: RuleCategory;
  check(sqlCall: SQLCall): AntiPattern[];
}
