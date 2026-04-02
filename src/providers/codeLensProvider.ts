import * as vscode from "vscode";
import { AnalysisCache } from "../analysis/analysisCache";

export class CodeLensProvider implements vscode.CodeLensProvider {
  constructor(private cache: AnalysisCache) {}

  async provideCodeLenses(
    document: vscode.TextDocument,
    _token: vscode.CancellationToken
  ): Promise<vscode.CodeLens[]> {
    const uri = document.uri.toString();
    const code = document.getText();
    const result = this.cache.getDetection(uri, document.version, code);
    const codeLenses: vscode.CodeLens[] = [];

    for (const query of result.queries) {

      const range = new vscode.Range(
        query.line - 1,
        query.column,
        query.line - 1,
        query.column + query.sql.length
      );

      // Preview CodeLens (only for SELECT queries)
      if (this.cache.detector.extractSQLType(query.sql) === "SELECT") {
        codeLenses.push(
          new vscode.CodeLens(range, {
            title: `$(search) Preview`,
            command: "sqlens.previewQuery",
            arguments: [query.sql, document.uri],
            tooltip: "Preview query results (limited to 5 rows)",
          })
        );
      }

      // Explain Plan CodeLens
      codeLenses.push(
        new vscode.CodeLens(range, {
          title: `$(graph) Explain`,
          command: "sqlens.explainQuery",
          arguments: [query.sql, document.uri],
          tooltip: "Show query execution plan",
        })
      );

      // Copy SQL CodeLens
      codeLenses.push(
        new vscode.CodeLens(range, {
          title: `$(copy) Copy`,
          command: "sqlens.copyQuery",
          arguments: [query.sql],
          tooltip: "Copy SQL query to clipboard",
        })
      );

      // Safety indicator - considers both injection safety and anti-patterns
      const antiPatterns = this.cache.getAntiPatterns(uri, document.version, code, query);
      const hasErrors = antiPatterns.some((ap) => ap.severity === "error");
      const hasWarnings = antiPatterns.some((ap) => ap.severity === "warning");

      let safetyTitle: string;
      let safetyTooltip: string;
      if (hasErrors) {
        safetyTitle = `$(error) Error (${antiPatterns.filter((ap) => ap.severity === "error").length})`;
        safetyTooltip = antiPatterns.filter((ap) => ap.severity === "error").map((ap) => ap.message).join("; ");
      } else if (hasWarnings || !query.isSafe) {
        safetyTitle = `$(warning) Warning (${antiPatterns.length})`;
        safetyTooltip = antiPatterns.length > 0
          ? antiPatterns.map((ap) => ap.message).join("; ")
          : "This query may have security issues";
      } else {
        safetyTitle = `$(check) Safe`;
        safetyTooltip = "This query appears to be safe";
      }

      codeLenses.push(
        new vscode.CodeLens(range, {
          title: safetyTitle,
          command: "sqlens.showSafetyInfo",
          arguments: [query],
          tooltip: safetyTooltip,
        })
      );
    }

    return codeLenses;
  }

  async resolveCodeLens(
    codeLens: vscode.CodeLens,
    _token: vscode.CancellationToken
  ): Promise<vscode.CodeLens> {
    return codeLens;
  }
}
