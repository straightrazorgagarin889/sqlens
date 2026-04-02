import * as vscode from "vscode";
import { AnalysisCache } from "../analysis/analysisCache";

export interface QuickFix {
  title: string;
  newText: string;
}

/**
 * Compute quick-fix suggestions for a given SQL string and rule type.
 * Pure function — testable without VS Code runtime.
 */
export function computeQuickFixes(sql: string, ruleType: string): QuickFix[] {
  switch (ruleType) {
    case "NULL_COMPARISON":
      return fixNullComparison(sql);
    case "UNION_VS_UNION_ALL":
      return fixUnionAll(sql);
    case "REDUNDANT_DISTINCT":
      return fixRedundantDistinct(sql);
    case "COUNT_FOR_EXISTS":
      return fixCountForExists(sql);
    default:
      return [];
  }
}

function fixNullComparison(sql: string): QuickFix[] {
  let fixed = sql;
  let changed = false;

  // Replace != NULL and <> NULL with IS NOT NULL (must come before = NULL)
  if (/(!= *|<> *)NULL\b/i.test(fixed)) {
    fixed = fixed.replace(/(!= *|<> *)NULL\b/gi, "IS NOT NULL");
    changed = true;
  }

  // Replace = NULL with IS NULL
  if (/(= *)NULL\b/i.test(fixed)) {
    fixed = fixed.replace(/(= *)NULL\b/gi, "IS NULL");
    changed = true;
  }

  if (!changed) { return []; }
  return [{ title: "Fix NULL comparison (use IS NULL / IS NOT NULL)", newText: fixed }];
}

function fixUnionAll(sql: string): QuickFix[] {
  if (!/\bUNION\b(?!\s+ALL)/i.test(sql)) { return []; }
  const fixed = sql.replace(/\bUNION\b(?!\s+ALL)/gi, "UNION ALL");
  return [{ title: "Replace UNION with UNION ALL", newText: fixed }];
}

function fixRedundantDistinct(sql: string): QuickFix[] {
  if (!/\bSELECT\s+DISTINCT\b/i.test(sql)) { return []; }
  const fixed = sql.replace(/\bSELECT\s+DISTINCT\b/i, "SELECT");
  return [{ title: "Remove redundant DISTINCT", newText: fixed }];
}

function fixCountForExists(sql: string): QuickFix[] {
  // Transform SELECT COUNT(*) FROM ... WHERE ... into SELECT EXISTS(SELECT 1 FROM ... WHERE ...)
  const match = sql.match(/\bSELECT\s+COUNT\s*\(\s*\*?\s*\)\s+(FROM\b.*)/i);
  if (!match) { return []; }
  const fixed = `SELECT EXISTS(SELECT 1 ${match[1]})`;
  return [{ title: "Replace COUNT(*) with EXISTS for existence check", newText: fixed }];
}

export class QuickFixProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  constructor(private cache: AnalysisCache) {}

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "SQLens") { continue; }

      const ruleType = String(diagnostic.code);
      const uri = document.uri.toString();
      const code = document.getText();
      const result = this.cache.getDetection(uri, document.version, code);

      const query = result.queries.find(q => q.line - 1 === diagnostic.range.start.line);
      if (!query) { continue; }

      const fixes = computeQuickFixes(query.sql, ruleType);
      for (const fix of fixes) {
        const action = new vscode.CodeAction(fix.title, vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        action.isPreferred = true;

        // Replace the SQL string within the source range
        const edit = new vscode.WorkspaceEdit();
        const sqlInSource = document.getText(diagnostic.range);
        const newSource = sqlInSource.replace(query.sql, fix.newText);
        edit.replace(document.uri, diagnostic.range, newSource);
        action.edit = edit;

        actions.push(action);
      }
    }

    return actions;
  }
}
