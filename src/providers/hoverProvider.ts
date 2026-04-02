import * as vscode from "vscode";
import { SQLCall } from "../analysis/phpAst";
import { AnalysisCache } from "../analysis/analysisCache";

export class HoverProvider implements vscode.HoverProvider {
  constructor(private cache: AnalysisCache) {}

  async provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken
  ): Promise<vscode.Hover | undefined> {
    const uri = document.uri.toString();
    const code = document.getText();
    const result = this.cache.getDetection(uri, document.version, code);

    const sqlQuery = result.queries.find(
      (query) => query.line - 1 === position.line
    );

    if (!sqlQuery) {
      return undefined;
    }

    const hover = this.createHoverInfo(sqlQuery, document);
    return new vscode.Hover(hover);
  }

  private createHoverInfo(sqlQuery: SQLCall, document: vscode.TextDocument): vscode.MarkdownString {
    const markdown = new vscode.MarkdownString();
    markdown.isTrusted = true;

    const detector = this.cache.detector;

    // SQL Query Summary
    markdown.appendMarkdown(`### SQL Query Analysis\n\n`);
    markdown.appendMarkdown(
      `**Type:** ${detector.extractSQLType(sqlQuery.sql)}\n\n`
    );
    markdown.appendMarkdown(`**Framework:** ${sqlQuery.framework}\n\n`);

    // Tables involved
    const tables = detector.extractTables(sqlQuery.sql);
    if (tables.length > 0) {
      markdown.appendMarkdown(`**Tables:** ${tables.join(", ")}\n\n`);
    }

    // Columns involved
    const columns = detector.extractColumns(sqlQuery.sql);
    if (columns.length > 0) {
      markdown.appendMarkdown(`**Columns:** ${columns.join(", ")}\n\n`);
    }

    // Safety information
    const safetyIcon = sqlQuery.isSafe ? "✅" : "⚠️";
    const safetyText = sqlQuery.isSafe ? "Safe" : "Potentially risky";
    markdown.appendMarkdown(`**Safety:** ${safetyIcon} ${safetyText}\n\n`);

    // Parameter binding
    const bindingIcon = sqlQuery.hasBinding ? "✅" : "❌";
    const bindingText = sqlQuery.hasBinding
      ? "Uses parameter binding"
      : "No parameter binding";
    markdown.appendMarkdown(
      `**Prepared Statement:** ${bindingIcon} ${bindingText}\n\n`
    );

    // ezSQL specific information
    if (sqlQuery.framework === "ezsql") {
      markdown.appendMarkdown(this.getEzSQLSpecificInfo(sqlQuery));
    }

    // Anti-patterns grouped by category
    const uri = document.uri.toString();
    const code = document.getText();
    const antiPatterns = this.cache.getAntiPatterns(uri, document.version, code, sqlQuery);
    if (antiPatterns.length > 0) {
      markdown.appendMarkdown(`### Issues Found\n\n`);

      const categoryLabels: Record<string, string> = {
        security: "Security",
        safety: "Data Safety",
        performance: "Performance",
        correctness: "Correctness",
        "best-practice": "Best Practice",
      };

      const grouped: Record<string, typeof antiPatterns> = {};
      for (const p of antiPatterns) {
        const cat = p.category || "other";
        if (!grouped[cat]) { grouped[cat] = []; }
        grouped[cat].push(p);
      }

      for (const [cat, patterns] of Object.entries(grouped)) {
        const label = categoryLabels[cat] || cat;
        markdown.appendMarkdown(`**${label}:**\n\n`);
        for (const pattern of patterns) {
          const severityIcon = this.getSeverityIcon(pattern.severity);
          markdown.appendMarkdown(
            `${severityIcon} ${pattern.message}\n\n`
          );
          if (pattern.suggestion) {
            markdown.appendMarkdown(`  *${pattern.suggestion}*\n\n`);
          }
        }
      }
    }

    // Quick actions
    markdown.appendMarkdown(`---\n\n`);
    markdown.appendMarkdown(
      `[Preview Query](command:sqlens.previewQuery?${encodeURIComponent(
        JSON.stringify([sqlQuery.sql, document.uri.toString()])
      )}) | `
    );
    markdown.appendMarkdown(
      `[Explain Plan](command:sqlens.explainQuery?${encodeURIComponent(
        JSON.stringify([sqlQuery.sql, document.uri.toString()])
      )})`
    );

    return markdown;
  }

  private getEzSQLSpecificInfo(sqlQuery: SQLCall): string {
    let info = `### ⚡ ezSQL Framework Information\n\n`;

    // Method-specific information
    switch (sqlQuery.method) {
      case "get_results":
        info += `**Method:** Returns multiple rows as an array of objects\n\n`;
        info += `**Example:** \`$db->get_results("SELECT * FROM users")\`\n\n`;
        info += `**Returns:** Array of stdClass objects\n\n`;
        break;
      case "get_row":
        info += `**Method:** Returns a single row as an object\n\n`;
        info += `**Example:** \`$db->get_row("SELECT * FROM users WHERE id=1")\`\n\n`;
        info += `**Returns:** Single stdClass object or null\n\n`;
        break;
      case "get_var":
        info += `**Method:** Returns a single variable (first column of first row)\n\n`;
        info += `**Example:** \`$db->get_var("SELECT COUNT(*) FROM users")\`\n\n`;
        info += `**Returns:** String/Number value or null\n\n`;
        break;
      case "get_col":
        info += `**Method:** Returns values from a single column as an array\n\n`;
        info += `**Example:** \`$db->get_col("SELECT name FROM users")\`\n\n`;
        info += `**Returns:** Array of column values\n\n`;
        break;
      case "query":
        info += `**Method:** Execute any SQL statement\n\n`;
        info += `**Example:** \`$db->query("INSERT INTO users VALUES (1, 'John')")\`\n\n`;
        info += `**Returns:** Result resource or boolean\n\n`;
        break;
      case "escape":
        info += `**Method:** ✅ Escapes strings for safe SQL usage\n\n`;
        info += `**Example:** \`$safe_input = $db->escape($user_input)\`\n\n`;
        info += `**Security:** Prevents SQL injection\n\n`;
        break;
      case "insert":
        info += `**Method:** Simplified INSERT operation\n\n`;
        info += `**Example:** \`$db->insert('users', array('name' => 'John'))\`\n\n`;
        break;
      case "update":
        info += `**Method:** Simplified UPDATE operation\n\n`;
        info += `**Example:** \`$db->update('users', array('name' => 'Jane'), array('id' => 1))\`\n\n`;
        break;
      case "delete":
        info += `**Method:** Simplified DELETE operation\n\n`;
        info += `**Example:** \`$db->delete('users', array('id' => 1))\`\n\n`;
        break;
    }

    // ezSQL features and tips
    info += `**💡 ezSQL Features:**\n`;
    info += `• Built-in query caching for performance\n`;
    info += `• Automatic connection management\n`;
    info += `• Cross-database compatibility\n`;
    info += `• Built-in debugging tools\n\n`;

    // Best practices
    info += `**📋 Best Practices:**\n`;
    info += `• Use \`$db->escape()\` for all user input\n`;
    info += `• Check \`$db->last_error\` after operations\n`;
    info += `• Use \`$db->show_errors()\` during development\n`;
    info += `• Leverage query caching for repeated queries\n\n`;

    // Performance tips
    info += `**⚡ Performance Tips:**\n`;
    info += `• Cache is disabled for queries with RAND(), NOW()\n`;
    info += `• Use specific column names instead of SELECT *\n`;
    info += `• Consider using get_var() for COUNT queries\n`;
    info += `• Use get_col() for single column results\n\n`;

    // Security recommendations
    if (!sqlQuery.isSafe) {
      info += `**🔒 Security Alert:**\n`;
      info += `• This query appears to have security risks\n`;
      info += `• Always escape user input: \`$db->escape($input)\`\n`;
      info += `• Avoid direct variable interpolation in SQL\n`;
      info += `• Consider parameterized queries when available\n\n`;
    }

    return info;
  }

  private getSeverityIcon(severity: string): string {
    switch (severity) {
      case "error":
        return "🚨";
      case "warning":
        return "⚠️";
      case "info":
        return "ℹ️";
      default:
        return "📝";
    }
  }
}
