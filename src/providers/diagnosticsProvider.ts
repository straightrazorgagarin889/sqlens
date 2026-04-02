import * as vscode from "vscode";
import { AnalysisCache } from "../analysis/analysisCache";

export class DiagnosticsProvider {
  private diagnosticCollection = vscode.languages.createDiagnosticCollection(
    "sqlens"
  );

  constructor(private cache: AnalysisCache) {}

  updateDiagnostics(document: vscode.TextDocument): void {
    if (document.languageId !== "php") {
      return;
    }

    const diagnostics: vscode.Diagnostic[] = [];
    const uri = document.uri.toString();
    const code = document.getText();
    const result = this.cache.getDetection(uri, document.version, code);

    for (const query of result.queries) {
      const antiPatterns = this.cache.getAntiPatterns(uri, document.version, code, query);

      for (const pattern of antiPatterns) {
        const range = new vscode.Range(
          pattern.line - 1,
          pattern.column,
          pattern.line - 1,
          pattern.column + query.sql.length
        );

        const diagnostic = new vscode.Diagnostic(
          range,
          pattern.message,
          this.mapSeverity(pattern.severity)
        );

        diagnostic.source = "SQLens";
        diagnostic.code = pattern.type;

        // Add related information if suggestion exists
        if (pattern.suggestion) {
          diagnostic.relatedInformation = [
            new vscode.DiagnosticRelatedInformation(
              new vscode.Location(document.uri, range),
              `Suggestion: ${pattern.suggestion}`
            ),
          ];
        }

        // Only use Unnecessary tag for genuinely unnecessary code patterns
        if (
          pattern.type === "SELECT_STAR" ||
          pattern.type === "REDUNDANT_DISTINCT"
        ) {
          diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
        }

        diagnostics.push(diagnostic);
      }

    }

    this.diagnosticCollection.set(document.uri, diagnostics);
  }

  private mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
      case "error":
        return vscode.DiagnosticSeverity.Error;
      case "warning":
        return vscode.DiagnosticSeverity.Warning;
      case "info":
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Hint;
    }
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
  }
}
