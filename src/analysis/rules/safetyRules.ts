import { SQLCall } from "../phpAst";
import { AntiPattern, RuleChecker } from "./ruleTypes";

export class SafetyRuleChecker implements RuleChecker {
  category = "safety" as const;

  private static readonly UPDATE_RE = /^\s*UPDATE\b/i;
  private static readonly DELETE_RE = /^\s*DELETE\b/i;
  private static readonly WHERE_RE = /\bWHERE\b/i;
  private static readonly DROP_RE = /\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE(\s+TABLE)?)\b/i;
  private static readonly INSERT_NO_COLS_RE = /INSERT\s+INTO\s+\w+\s+VALUES\b/i;
  private static readonly INSERT_WITH_COLS_RE = /INSERT\s+INTO\s+\w+\s*\(/i;
  private static readonly ERROR_DISCLOSURE_RE = /\b(die|exit|echo|print|var_dump|print_r)\s*\([\s\S]*?(mysql_error|mysqli_error|pg_last_error|->errorInfo|->getMessage|SQLSTATE)/i;
  private static readonly REPLACE_RE = /^\s*REPLACE\s+INTO\b/i;
  private static readonly ALTER_DROP_COL_RE = /\bALTER\s+TABLE\s+\w+\s+DROP\s+(COLUMN\s+)?\w+/i;
  private static readonly RENAME_TABLE_RE = /\bRENAME\s+TABLE\b/i;

  check(sqlCall: SQLCall): AntiPattern[] {
    const patterns: AntiPattern[] = [];

    patterns.push(...this.checkUpdateNoWhere(sqlCall));
    patterns.push(...this.checkDeleteNoWhere(sqlCall));
    patterns.push(...this.checkDestructiveDDL(sqlCall));
    patterns.push(...this.checkInsertNoColumns(sqlCall));
    patterns.push(...this.checkErrorDisclosure(sqlCall));
    patterns.push(...this.checkReplaceStatement(sqlCall));
    patterns.push(...this.checkAlterDropColumn(sqlCall));

    return patterns;
  }

  private checkUpdateNoWhere(sqlCall: SQLCall): AntiPattern[] {
    if (!SafetyRuleChecker.UPDATE_RE.test(sqlCall.sql)) { return []; }
    if (SafetyRuleChecker.WHERE_RE.test(sqlCall.sql)) { return []; }

    return [{
      type: "UPDATE_NO_WHERE",
      category: "safety",
      severity: "error",
      message: "UPDATE without WHERE clause will modify every row in the table.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Add a WHERE clause to limit which rows are updated",
    }];
  }

  private checkDeleteNoWhere(sqlCall: SQLCall): AntiPattern[] {
    if (!SafetyRuleChecker.DELETE_RE.test(sqlCall.sql)) { return []; }
    if (SafetyRuleChecker.WHERE_RE.test(sqlCall.sql)) { return []; }

    return [{
      type: "DELETE_NO_WHERE",
      category: "safety",
      severity: "error",
      message: "DELETE without WHERE clause will remove every row from the table.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Add a WHERE clause to limit which rows are deleted",
    }];
  }

  private checkDestructiveDDL(sqlCall: SQLCall): AntiPattern[] {
    const match = sqlCall.sql.match(SafetyRuleChecker.DROP_RE);
    if (!match) { return []; }

    const operation = match[0].toUpperCase();
    return [{
      type: "DESTRUCTIVE_DDL",
      category: "safety",
      severity: "error",
      message: `${operation} detected in application code. This is a destructive operation that cannot be undone.`,
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use migration scripts for schema changes, not application code",
    }];
  }

  private checkInsertNoColumns(sqlCall: SQLCall): AntiPattern[] {
    if (!SafetyRuleChecker.INSERT_NO_COLS_RE.test(sqlCall.sql)) { return []; }
    if (SafetyRuleChecker.INSERT_WITH_COLS_RE.test(sqlCall.sql)) { return []; }

    return [{
      type: "INSERT_NO_COLUMNS",
      category: "safety",
      severity: "warning",
      message: "INSERT without explicit column list is fragile. Schema changes will break this query.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Specify column names: INSERT INTO table (col1, col2) VALUES (...)",
    }];
  }

  private checkErrorDisclosure(sqlCall: SQLCall): AntiPattern[] {
    const ctx = sqlCall.surroundingCode;
    if (!ctx) { return []; }
    if (!SafetyRuleChecker.ERROR_DISCLOSURE_RE.test(ctx)) { return []; }

    return [{
      type: "ERROR_DISCLOSURE",
      category: "safety",
      severity: "warning",
      message: "SQL error message may be exposed to the user. This leaks database structure information.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Log errors server-side. Show generic error messages to users",
    }];
  }

  private checkReplaceStatement(sqlCall: SQLCall): AntiPattern[] {
    if (!SafetyRuleChecker.REPLACE_RE.test(sqlCall.sql)) { return []; }
    return [{
      type: "REPLACE_STATEMENT",
      category: "safety",
      severity: "warning",
      message: "REPLACE INTO deletes existing rows before inserting. This can trigger DELETE cascades and lose data.",
      line: sqlCall.line,
      column: sqlCall.column,
      suggestion: "Use INSERT ... ON DUPLICATE KEY UPDATE for safer upsert behavior",
    }];
  }

  private checkAlterDropColumn(sqlCall: SQLCall): AntiPattern[] {
    const patterns: AntiPattern[] = [];

    if (SafetyRuleChecker.ALTER_DROP_COL_RE.test(sqlCall.sql)) {
      patterns.push({
        type: "ALTER_DROP_COLUMN",
        category: "safety",
        severity: "error",
        message: "ALTER TABLE DROP COLUMN is destructive and irreversible. All data in the column will be lost.",
        line: sqlCall.line,
        column: sqlCall.column,
        suggestion: "Use migration scripts with backup. Consider marking column as deprecated instead",
      });
    }

    if (SafetyRuleChecker.RENAME_TABLE_RE.test(sqlCall.sql)) {
      patterns.push({
        type: "ALTER_DROP_COLUMN",
        category: "safety",
        severity: "warning",
        message: "RENAME TABLE in application code can break other queries referencing the old name.",
        line: sqlCall.line,
        column: sqlCall.column,
        suggestion: "Use migration scripts for table renames. Create views with old names for backward compatibility",
      });
    }

    return patterns;
  }
}
