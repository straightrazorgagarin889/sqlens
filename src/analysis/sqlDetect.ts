import { PHPASTAnalyzer, SQLCall } from "./phpAst";
import { TaintAnalyzer } from "./taint";

export interface SQLDetectionResult {
  queries: SQLCall[];
  totalQueries: number;
  riskyQueries: number;
  safeQueries: number;
}

export class SQLDetector {
  private phpAnalyzer = new PHPASTAnalyzer();
  private taintAnalyzer = new TaintAnalyzer();

  detectSQLInDocument(code: string): SQLDetectionResult {
    const queries = this.phpAnalyzer.analyzePHPCode(code);

    // Taint analysis: track variable flows from superglobals to SQL sinks
    const taintFlows = this.taintAnalyzer.analyzeTaintFlow(code, queries);
    for (const flow of taintFlows) {
      const q = queries.find((query) => query.line === flow.sink.line);
      if (q && q.isSafe) {
        q.isSafe = false;
      }
    }

    const riskyQueries = queries.filter((q) => !q.isSafe).length;
    const safeQueries = queries.filter((q) => q.isSafe).length;

    return {
      queries,
      totalQueries: queries.length,
      riskyQueries,
      safeQueries,
    };
  }

  isValidSQL(sql: string): boolean {
    // Basic SQL validation
    const trimmed = sql.trim().toLowerCase();
    const sqlKeywords = [
      "select",
      "insert",
      "update",
      "delete",
      "create",
      "drop",
      "alter",
      "show",
      "replace", "truncate", "explain", "describe",
      "set", "use", "begin", "commit", "rollback", "savepoint",
      "call", "execute", "with", "lock", "unlock",
      "grant", "revoke", "rename", "start",
    ];

    return sqlKeywords.some((keyword) => trimmed.startsWith(keyword));
  }

  private static readonly SQL_TYPE_PREFIXES: Array<[string, string]> = [
    ["select", "SELECT"],
    ["insert", "INSERT"],
    ["update", "UPDATE"],
    ["delete", "DELETE"],
    ["create", "CREATE"],
    ["drop", "DROP"],
    ["alter", "ALTER"],
    ["show", "SHOW"],
    ["replace", "REPLACE"],
    ["truncate", "TRUNCATE"],
    ["explain", "EXPLAIN"],
    ["describe", "EXPLAIN"],
    ["desc ", "EXPLAIN"],
    ["set ", "SET"],
    ["set@", "SET"],
    ["use ", "USE"],
    ["begin", "BEGIN"],
    ["start transaction", "BEGIN"],
    ["commit", "COMMIT"],
    ["rollback", "ROLLBACK"],
    ["savepoint", "ROLLBACK"],
    ["call ", "CALL"],
    ["execute", "EXECUTE"],
    ["with ", "WITH"],
    ["lock", "LOCK"],
    ["unlock", "UNLOCK"],
    ["grant", "GRANT"],
    ["revoke", "REVOKE"],
    ["rename", "RENAME"],
  ];

  extractSQLType(sql: string): string {
    const trimmed = sql.trim().toLowerCase();

    for (const [prefix, type] of SQLDetector.SQL_TYPE_PREFIXES) {
      if (trimmed.startsWith(prefix)) {
        return type;
      }
    }

    return "UNKNOWN";
  }

  private static readonly TABLE_PATTERNS: RegExp[] = [
    /FROM\s+(?:`?\w+`?\.)?`?([a-zA-Z_][a-zA-Z0-9_]*)`?/gi,
    /JOIN\s+(?:`?\w+`?\.)?`?([a-zA-Z_][a-zA-Z0-9_]*)`?/gi,
    /UPDATE\s+(?:`?\w+`?\.)?`?([a-zA-Z_][a-zA-Z0-9_]*)`?/gi,
    /INSERT\s+INTO\s+(?:`?\w+`?\.)?`?([a-zA-Z_][a-zA-Z0-9_]*)`?/gi,
    /DELETE\s+FROM\s+(?:`?\w+`?\.)?`?([a-zA-Z_][a-zA-Z0-9_]*)`?/gi,
    /REPLACE\s+INTO\s+(?:`?\w+`?\.)?`?([a-zA-Z_][a-zA-Z0-9_]*)`?/gi,
    /TRUNCATE\s+(?:TABLE\s+)?(?:`?\w+`?\.)?`?([a-zA-Z_][a-zA-Z0-9_]*)`?/gi,
  ];

  extractTables(sql: string): string[] {
    const tables: string[] = [];

    for (const pattern of SQLDetector.TABLE_PATTERNS) {
      // Reset lastIndex since patterns have the 'g' flag
      pattern.lastIndex = 0;
      const matches = sql.match(pattern);
      if (matches) {
        for (const match of matches) {
          const raw = match.split(/\s+/).pop()?.replace(/`/g, "") ?? "";
          const table = raw.includes(".") ? raw.split(".").pop()! : raw;
          if (table && !tables.includes(table)) {
            tables.push(table);
          }
        }
      }
    }

    return tables;
  }

  extractColumns(sql: string): string[] {
    const columns: string[] = [];

    // Extract SELECT columns
    const selectMatch = sql.match(/SELECT\s+(.*?)\s+FROM/i);
    if (selectMatch) {
      const columnsPart = selectMatch[1];

      if (columnsPart.trim() === "*") {
        columns.push("*");
      } else {
        const columnList = columnsPart.split(",").map((col) => col.trim());
        columns.push(...columnList);
      }
    }

    return columns;
  }
}
