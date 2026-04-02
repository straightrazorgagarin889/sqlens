import { Engine } from "php-parser";

export interface SQLCall {
  sql: string;
  line: number;
  column: number;
  framework: string;
  method: string;
  hasBinding: boolean;
  isSafe: boolean;
  variables: string[];
  enclosingLoop: boolean;
  loopType: string | null;
  surroundingCode: string;
  usesSprintfInterpolation: boolean;
}

export class PHPASTAnalyzer {
  private parser = new Engine({
    parser: {
      extractDoc: true,
      php7: true,
    },
    ast: {
      withPositions: true,
    },
  });

  private sourceLines: string[] = [];
  private variableMap: Map<string, string> = new Map();

  analyzePHPCode(code: string): SQLCall[] {
    try {
      this.variableMap = new Map();
      this.sourceLines = code.split("\n");
      const ast = this.parser.parseCode(code, "");
      const sqlCalls: SQLCall[] = [];
      this.traverseAST(ast, sqlCalls, { inLoop: false, loopType: null });
      return sqlCalls;
    } catch {
      return [];
    }
  }

  private traverseAST(
    node: any,
    sqlCalls: SQLCall[],
    ctx: { inLoop: boolean; loopType: string | null }
  ): void {
    if (!node || typeof node !== "object") {
      return;
    }

    // Track loop context
    const loopKinds = ["for", "foreach", "while", "do"];
    if (loopKinds.includes(node.kind)) {
      const loopCtx = { inLoop: true, loopType: node.kind };
      for (const key in node) {
        if (key === "loc" || key === "kind") { continue; }
        const value = node[key];
        if (Array.isArray(value)) {
          value.forEach((child) => this.traverseAST(child, sqlCalls, loopCtx));
        } else if (typeof value === "object") {
          this.traverseAST(value, sqlCalls, loopCtx);
        }
      }
      return;
    }

    if (node.kind === "assign" || node.kind === "expressionstatement" && node.expression?.kind === "assign") {
      const assignNode = node.kind === "assign" ? node : node.expression;
      if (assignNode?.left?.kind === "variable" && assignNode?.right) {
        const varName = "$" + assignNode.left.name;
        const value = this.extractStringValueFromNode(assignNode.right);
        if (value) {
          this.variableMap.set(varName, value);
        }
      }
    }

    if (node.kind === "call") {
      const sqlCall = this.analyzeMethodCall(node);
      if (sqlCall) {
        sqlCall.enclosingLoop = ctx.inLoop;
        sqlCall.loopType = ctx.loopType;
        sqlCall.surroundingCode = this.getSurroundingCode(sqlCall.line);
        sqlCalls.push(sqlCall);
      }
    }

    for (const key in node) {
      if (Object.prototype.hasOwnProperty.call(node, key)) {
        const value = node[key];
        if (Array.isArray(value)) {
          value.forEach((child) => this.traverseAST(child, sqlCalls, ctx));
        } else if (typeof value === "object") {
          this.traverseAST(value, sqlCalls, ctx);
        }
      }
    }
  }

  private getSurroundingCode(line: number): string {
    const start = Math.max(0, line - 6);
    const end = Math.min(this.sourceLines.length, line + 5);
    return this.sourceLines.slice(start, end).join("\n");
  }

  private analyzeMethodCall(node: any): SQLCall | null {
    try {
      const methodName = this.getMethodName(node);
      const framework = this.detectFramework(node, methodName);

      if (!this.isSQLMethod(framework, methodName)) {
        return null;
      }

      const sqlString = this.extractSQLString(node);

      // Non-SQL ezSQL methods (hide_errors, debug, vardump) - include for anti-pattern detection
      const ezSQLNonQueryMethods = ["hide_errors", "show_errors", "debug", "vardump", "flush"];
      if (!sqlString) {
        if (framework === "ezsql" && ezSQLNonQueryMethods.includes(methodName)) {
          return {
            sql: "",
            line: node.loc?.start?.line || 0,
            column: node.loc?.start?.column || 0,
            framework,
            method: methodName,
            hasBinding: false,
            isSafe: true,
            variables: [],
            enclosingLoop: false,
            loopType: null,
            surroundingCode: "",
            usesSprintfInterpolation: false,
          };
        }
        return null;
      }

      const variables = this.extractVariables(node);
      const hasBinding = this.hasParameterBinding(node, methodName);
      const isSafe = this.isSafeQuery(
        sqlString,
        variables,
        hasBinding,
        framework,
        methodName
      );

      const usesSprintfInterpolation = this.detectSprintfInterpolation(node);

      return {
        sql: sqlString,
        line: node.loc?.start?.line || 0,
        column: node.loc?.start?.column || 0,
        framework,
        method: methodName,
        hasBinding,
        isSafe,
        variables,
        enclosingLoop: false,
        loopType: null,
        surroundingCode: "",
        usesSprintfInterpolation,
      };
    } catch {
      return null;
    }
  }

  private getMethodName(node: any): string {
    if (
      (node.what?.kind === "propertylookup" || node.what?.kind === "staticlookup") &&
      node.what?.offset?.name
    ) {
      return node.what.offset.name;
    }

    if (node.what?.name) {
      return node.what.name;
    }

    if (node.what?.property?.name) {
      return node.what.property.name;
    }

    if (node.what?.kind === "identifier" && node.what?.name) {
      return node.what.name;
    }

    return "";
  }

  private detectFramework(node: any, methodName: string): string {
    let objectName = "";
    // Handle chained property lookups: $this->wpdb->method()
    // In this case node.what.what is also a propertylookup, and we want the intermediate property name
    if (node.what?.kind === "propertylookup" && node.what?.what?.kind === "propertylookup") {
      // $this->wpdb->method() => intermediate property is "wpdb"
      const intermediateName = node.what.what.offset?.name;
      if (intermediateName) {
        objectName = "$" + intermediateName;
      }
    } else if (node.what?.kind === "propertylookup" && node.what?.what?.name) {
      objectName = "$" + node.what.what.name;
    } else if (node.what?.kind === "staticlookup" && node.what?.what?.name) {
      objectName = node.what.what.name;
    } else if (node.what?.object?.name) {
      objectName = node.what.object.name;
    }

    // WordPress patterns - Check BEFORE ezSQL since both share get_results/get_row/get_var
    if (objectName === "$wpdb" || methodName.includes("wpdb")) {
      return "wordpress";
    }

    // ezSQL patterns
    if (
      methodName === "get_results" ||
      methodName === "get_row" ||
      methodName === "get_var" ||
      methodName === "get_col" ||
      methodName === "escape" ||
      methodName === "insert" ||
      methodName === "update" ||
      methodName === "delete" ||
      methodName === "replace" ||
      methodName === "show_errors" ||
      methodName === "hide_errors" ||
      methodName === "flush" ||
      methodName === "debug"
    ) {
      if (
        objectName.startsWith("$db") ||
        objectName.includes("ezsql") ||
        objectName.includes("ezSQL") ||
        this.isEzSQLObjectPattern(objectName)
      ) {
        return "ezsql";
      }

      if (
        methodName === "get_results" ||
        methodName === "get_row" ||
        methodName === "get_var" ||
        methodName === "get_col"
      ) {
        return "ezsql";
      }
    }

    // Laravel patterns
    if (objectName === "DB") {
      return "laravel-db";
    }
    if (
      methodName === "raw" ||
      methodName === "whereRaw" ||
      methodName === "selectRaw" ||
      methodName === "orderByRaw" ||
      methodName === "groupByRaw" ||
      methodName === "havingRaw"
    ) {
      return "laravel-db";
    }

    // MySQLi-specific methods (not shared with PDO)
    if (methodName === "real_query" || methodName === "multi_query") {
      return "mysqli";
    }

    // MySQLi by object name hint
    if (/mysqli/i.test(objectName) && ["query", "prepare"].includes(methodName)) {
      return "mysqli";
    }

    // MySQLi procedural functions
    if (this.isMySQLiProceduralFunction(methodName)) {
      return "mysqli";
    }

    // Doctrine ORM patterns
    const doctrineMethods = [
      "createQuery", "createNativeQuery",
      "executeQuery", "executeStatement",
      "fetchAllAssociative", "fetchAllNumeric", "fetchAllKeyValue",
      "fetchAssociative", "fetchNumeric", "fetchOne",
      "fetchFirstColumn",
    ];
    if (doctrineMethods.includes(methodName)) {
      return "doctrine";
    }

    // PDO / generic DB methods (fallback)
    if (["query", "prepare", "exec"].includes(methodName)) {
      return "pdo";
    }

    return "unknown";
  }

  private isMySQLiProceduralFunction(name: string): boolean {
    const mysqliProcedural = [
      "mysqli_query", "mysqli_prepare", "mysqli_real_query",
      "mysqli_real_escape_string", "mysqli_multi_query",
    ];
    return mysqliProcedural.includes(name);
  }

  private isEzSQLObjectPattern(name: string): boolean {
    if (!name) {
      return false;
    }

    const ezSQLPatterns = [
      /^\$database$/i,
      /^\$sql$/i,
      /^\$ezsql/i,
      /^\$ez_sql/i,
      /^\$connection$/i,
      /\bdb_/i,
      /_db$/i,
    ];

    return ezSQLPatterns.some((pattern) => pattern.test(name));
  }

  private isSQLMethod(framework: string, methodName: string): boolean {
    const sqlMethods: { [key: string]: string[] } = {
      wordpress: ["get_results", "get_row", "get_var", "get_col", "query", "prepare"],
      "laravel-db": [
        "select",
        "insert",
        "update",
        "delete",
        "statement",
        "raw",
        "whereRaw",
        "selectRaw",
        "orderByRaw",
        "groupByRaw",
        "havingRaw",
        "unprepared",
      ],
      doctrine: [
        "createQuery", "createNativeQuery",
        "executeQuery", "executeStatement",
        "fetchAllAssociative", "fetchAllNumeric", "fetchAllKeyValue",
        "fetchAssociative", "fetchNumeric", "fetchOne",
        "fetchFirstColumn",
        "query", "prepare", "exec",
      ],
      pdo: ["query", "prepare", "exec"],
      mysqli: ["query", "prepare", "real_query", "multi_query", "mysqli_query", "mysqli_prepare", "mysqli_real_query", "mysqli_multi_query"],
      ezsql: [
        "get_results",
        "get_row",
        "get_var",
        "get_col",
        "query",
        "prepare",
        "escape",
        "insert",
        "update",
        "delete",
        "replace",
        "show_errors",
        "hide_errors",
        "flush",
        "debug",
        "vardump",
      ],
      unknown: [
        "get_results",
        "get_row",
        "get_var",
        "get_col",
        "query",
        "prepare",
      ],
    };

    return sqlMethods[framework]?.includes(methodName) || false;
  }

  private extractSQLString(node: any): string | null {
    if (node.arguments && node.arguments.length > 0) {
      const methodName = this.getMethodName(node);
      // MySQLi procedural functions have SQL as second argument
      const sqlArgIndex = this.isMySQLiProceduralFunction(methodName) && node.arguments.length >= 2 ? 1 : 0;
      const firstArg = node.arguments[sqlArgIndex];

      if (firstArg.kind === "string") {
        return firstArg.value;
      }

      if (firstArg.kind === "bin" && firstArg.type === ".") {
        return this.extractConcatenatedString(firstArg);
      }

      if (firstArg.kind === "encapsed") {
        return this.extractEncapsedString(firstArg);
      }

      if (firstArg.kind === "nowdoc") {
        return firstArg.value;
      }

      // Handle sprintf() as first argument: db->query(sprintf("SELECT ... %s", $var))
      if (firstArg.kind === "call" && firstArg.what?.name === "sprintf") {
        if (firstArg.arguments?.[0]?.kind === "string") {
          return firstArg.arguments[0].value;
        }
      }

      // Handle variable argument: $pdo->query($sql)
      if (firstArg.kind === "variable") {
        const varName = "$" + firstArg.name;
        return this.variableMap.get(varName) || null;
      }
    }

    return null;
  }

  private extractStringValueFromNode(node: any): string | null {
    if (!node) { return null; }
    if (node.kind === "string") {
      return node.value;
    }
    if (node.kind === "bin" && node.type === ".") {
      return this.extractConcatenatedString(node);
    }
    if (node.kind === "encapsed") {
      return this.extractEncapsedString(node);
    }
    if (node.kind === "nowdoc") {
      return node.value;
    }
    return null;
  }

  private extractConcatenatedString(node: any): string {
    let result = "";

    if (node.left?.kind === "string") {
      result += node.left.value;
    } else if (node.left?.kind === "bin") {
      result += this.extractConcatenatedString(node.left);
    } else if (node.left?.kind === "variable") {
      result += "$" + node.left.name;
    } else if (node.left?.kind === "offsetlookup" && node.left?.what?.kind === "variable") {
      result += "$" + node.left.what.name;
    }

    if (node.right?.kind === "string") {
      result += node.right.value;
    } else if (node.right?.kind === "bin") {
      result += this.extractConcatenatedString(node.right);
    } else if (node.right?.kind === "variable") {
      result += "$" + node.right.name;
    } else if (node.right?.kind === "offsetlookup" && node.right?.what?.kind === "variable") {
      result += "$" + node.right.what.name;
    }

    return result;
  }

  private extractEncapsedString(node: any): string {
    let result = "";

    if (node.value && Array.isArray(node.value)) {
      for (const part of node.value) {
        if (part.kind === "string") {
          result += part.value;
        } else if (part.kind === "variable") {
          result += `$${part.name}`;
        } else {
          result += "[EXPR]";
        }
      }
    }

    return result;
  }

  private extractVariables(node: any): string[] {
    const variables: string[] = [];
    this.collectVariablesFromNode(node, variables);
    return [...new Set(variables)];
  }

  private collectVariablesFromNode(node: any, variables: string[]): void {
    if (!node || typeof node !== "object") {
      return;
    }

    if (node.kind === "variable") {
      const name = "$" + node.name;
      variables.push(name);
      return;
    }

    if (node.kind === "encapsed" && Array.isArray(node.value)) {
      for (const part of node.value) {
        if (part.kind === "variable") {
          variables.push("$" + part.name);
        }
      }
      return;
    }

    for (const key in node) {
      if (key === "loc" || key === "kind") {
        continue;
      }
      const value = node[key];
      if (Array.isArray(value)) {
        value.forEach((child) => this.collectVariablesFromNode(child, variables));
      } else if (typeof value === "object") {
        this.collectVariablesFromNode(value, variables);
      }
    }
  }

  private hasParameterBinding(node: any, methodName: string): boolean {
    // Methods that inherently use parameter binding
    if (methodName === "prepare") {
      return true;
    }

    // Check for array/placeholder arguments that indicate binding
    if (node.arguments && node.arguments.length > 1) {
      const secondArg = node.arguments[1];
      // Array literal = binding parameters
      if (secondArg.kind === "array") {
        return true;
      }
      // Variable that is likely a params array
      if (secondArg.kind === "variable") {
        return true;
      }
    }

    return false;
  }

  private isSafeQuery(
    sql: string,
    _variables: string[],
    hasBinding: boolean,
    framework?: string,
    methodName?: string
  ): boolean {
    // ezSQL specific safety checks
    if (framework === "ezsql") {
      return this.isEzSQLSafeQuery(sql, methodName || "");
    }

    // Prepared statements are generally safe
    if (hasBinding) {
      return true;
    }

    // Check for dangerous patterns
    const dangerousPatterns = [
      /\$_GET/gi,
      /\$_POST/gi,
      /\$_REQUEST/gi,
      /\$_COOKIE/gi,
      /\$_SERVER/gi,
    ];

    return !dangerousPatterns.some((pattern) => pattern.test(sql));
  }

  private isEzSQLSafeQuery(sql: string, methodName: string): boolean {
    const safeEzSQLMethods = ["escape", "prepare"];

    if (safeEzSQLMethods.includes(methodName)) {
      return true;
    }

    if (sql.includes("$db->escape(") || sql.includes("->escape(")) {
      return true;
    }

    const ezSQLDangerousPatterns = [
      /\$_GET/gi,
      /\$_POST/gi,
      /\$_REQUEST/gi,
      /\$_COOKIE/gi,
      /\$_SERVER/gi,
      /\$_SESSION/gi,
      /\$.*\s*\.\s*['"][^'"]*\$.*['"]/,
      /["'].*\$.*['"]/,
    ];

    const hasDangerousPatterns = ezSQLDangerousPatterns.some((pattern) =>
      pattern.test(sql)
    );

    const hasEscaping = this.checkEzSQLEscaping(sql);
    const hasProperQuoting = this.checkEzSQLQuoting(sql);

    if (hasDangerousPatterns) {
      return hasEscaping || hasProperQuoting;
    }
    // No dangerous patterns found - query is safe
    return true;
  }

  private checkEzSQLEscaping(sql: string): boolean {
    const escapingPatterns = [
      /escape\s*\(/gi,
      /addslashes\s*\(/gi,
      /mysql_real_escape_string\s*\(/gi,
      /mysqli_real_escape_string\s*\(/gi,
    ];

    return escapingPatterns.some((pattern) => pattern.test(sql));
  }

  private checkEzSQLQuoting(sql: string): boolean {
    const quotingPatterns = [
      /'%s'/gi,
      /'%d'/gi,
      /\$db->quote\(/gi,
    ];

    return quotingPatterns.some((pattern) => pattern.test(sql));
  }

  private detectSprintfInterpolation(node: any): boolean {
    if (!node.arguments || node.arguments.length === 0) {
      return false;
    }
    const firstArg = node.arguments[0];
    // Check if first argument is a sprintf() call
    if (firstArg.kind === "call" && firstArg.what?.name === "sprintf") {
      return true;
    }
    return false;
  }
}
