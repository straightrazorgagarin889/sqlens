import * as vscode from "vscode";
import { ConfigManager } from "../utils/config";
import { DatabaseConnection } from "../db/types";
import { MySQLConnection } from "../db/mysql";
import { PostgreSQLConnection } from "../db/pg";

export class ExplainWebviewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "sqlensExplainView";

  private _view?: vscode.WebviewView;

  constructor(private readonly _extensionContext: vscode.ExtensionContext) {}

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionContext.extensionUri],
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    webviewView.webview.onDidReceiveMessage(
      (message) => {
        switch (message.type) {
          case "explain":
            this.handleExplainRequest(message.sql);
            break;
        }
      },
      undefined,
      this._extensionContext.subscriptions
    );
  }

  public showExplainPlan(sql: string) {
    if (this._view) {
      this._view.show?.(true);
      this._view.webview.postMessage({ type: "showExplain", sql: sql });
    } else {
      this.showInOutputChannel(sql, null);
    }
  }

  public showExplainResult(result: {
    query: string;
    plan: any[];
    warnings: string[];
    suggestions: string[];
  }) {
    if (this._view) {
      this._view.show?.(true);
      this._view.webview.postMessage({ type: "explainResult", result });
    } else {
      this.showInOutputChannel(result.query, result);
    }
  }

  private showInOutputChannel(
    sql: string,
    result: { query: string; plan: any[]; warnings: string[]; suggestions: string[] } | null
  ) {
    const output = vscode.window.createOutputChannel("SQLens - Explain");
    output.clear();
    output.appendLine("-- SQL Explain Plan --\n");
    output.appendLine(sql);

    if (result) {
      if (result.plan.length > 0) {
        output.appendLine("\n-- Execution Plan --");
        const keys = Object.keys(result.plan[0]);
        output.appendLine(keys.join("\t"));
        output.appendLine("-".repeat(keys.length * 15));
        for (const row of result.plan) {
          output.appendLine(keys.map((k) => String(row[k] ?? "")).join("\t"));
        }
      }

      if (result.warnings.length > 0) {
        output.appendLine("\n-- Warnings --");
        for (const w of result.warnings) {
          output.appendLine(`[WARN] ${w}`);
        }
      }

      if (result.suggestions.length > 0) {
        output.appendLine("\n-- Suggestions --");
        for (const s of result.suggestions) {
          output.appendLine(`-> ${s}`);
        }
      }
    }

    output.show(true);
  }

  private async handleExplainRequest(sql: string) {
    const config = new ConfigManager();
    const driver = config.get<string>("schema.driver");
    const db: DatabaseConnection = driver === "postgresql"
      ? new PostgreSQLConnection()
      : new MySQLConnection();

    try {
      await db.connect();
      const plan = await db.explainQuery(sql);

      const warnings: string[] = [];
      const suggestions: string[] = [];

      for (const row of plan) {
        if (row.type === "ALL" || row.Type === "ALL") {
          warnings.push("Full table scan detected");
          suggestions.push("Consider adding an index on the filtered columns");
        }
        if (row.key === null && row.Key === null) {
          warnings.push("No index used for this query");
        }
      }

      this._view?.webview.postMessage({
        type: "explainResult",
        result: { query: sql, plan, warnings, suggestions },
      });
    } catch (error) {
      this._view?.webview.postMessage({
        type: "error",
        message: `Explain failed: ${error instanceof Error ? error.message : error}. Check your database connection settings.`,
      });
    } finally {
      await db.disconnect();
    }
  }

  private _getHtmlForWebview(_webview: vscode.Webview) {
    return `<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SQL Explain Plan</title>
        <style>
            body {
                font-family: var(--vscode-font-family);
                font-size: var(--vscode-font-size);
                color: var(--vscode-foreground);
                background-color: var(--vscode-editor-background);
                padding: 10px;
                margin: 0;
            }
            
            .explain-container {
                margin-bottom: 20px;
            }
            
            .sql-query {
                background-color: var(--vscode-textCodeBlock-background);
                border: 1px solid var(--vscode-panel-border);
                border-radius: 4px;
                padding: 10px;
                font-family: var(--vscode-editor-font-family);
                font-size: var(--vscode-editor-font-size);
                margin-bottom: 15px;
                white-space: pre-wrap;
                overflow-x: auto;
            }
            
            .explain-table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 15px;
            }
            
            .explain-table th,
            .explain-table td {
                border: 1px solid var(--vscode-panel-border);
                padding: 8px;
                text-align: left;
                font-size: 12px;
            }
            
            .explain-table th {
                background-color: var(--vscode-button-background);
                color: var(--vscode-button-foreground);
                font-weight: bold;
            }
            
            .warnings {
                background-color: var(--vscode-inputValidation-warningBackground);
                border: 1px solid var(--vscode-inputValidation-warningBorder);
                border-radius: 4px;
                padding: 10px;
                margin-bottom: 15px;
            }
            
            .suggestions {
                background-color: var(--vscode-inputValidation-infoBackground);
                border: 1px solid var(--vscode-inputValidation-infoBorder);
                border-radius: 4px;
                padding: 10px;
            }
            
            .empty-state {
                text-align: center;
                color: var(--vscode-descriptionForeground);
                padding: 40px 20px;
            }
            
            .section-title {
                font-weight: bold;
                margin-bottom: 10px;
                color: var(--vscode-foreground);
            }
            
            ul {
                margin: 5px 0;
                padding-left: 20px;
            }
        </style>
    </head>
    <body>
        <div id="content">
            <div class="empty-state">
                <p>📊 SQL Explain Plan Viewer</p>
                <p>Select a query and click "Explain" to see the execution plan.</p>
            </div>
        </div>

        <script>
            const vscode = acquireVsCodeApi();

            function escapeHtml(str) {
                const div = document.createElement('div');
                div.appendChild(document.createTextNode(str));
                return div.innerHTML;
            }

            window.addEventListener('message', event => {
                const message = event.data;
                
                switch (message.type) {
                    case 'showExplain':
                        showExplainRequest(message.sql);
                        break;
                    case 'explainResult':
                        showExplainResult(message.result);
                        break;
                    case 'error':
                        showError(message.message);
                        break;
                }
            });
            
            function showExplainRequest(sql) {
                document.getElementById('content').innerHTML = \`
                    <div class="explain-container">
                        <div class="section-title">SQL Query</div>
                        <div class="sql-query">\${escapeHtml(sql)}</div>
                        <p>Running EXPLAIN...</p>
                    </div>
                \`;
                
                vscode.postMessage({ type: 'explain', sql: sql });
            }
            
            function showExplainResult(result) {
                const warningsHtml = result.warnings.length > 0 ? \`
                    <div class="warnings">
                        <div class="section-title">⚠️ Warnings</div>
                        <ul>
                            \${result.warnings.map(w => \`<li>\${escapeHtml(w)}</li>\`).join('')}
                        </ul>
                    </div>
                \` : '';

                const suggestionsHtml = result.suggestions.length > 0 ? \`
                    <div class="suggestions">
                        <div class="section-title">💡 Suggestions</div>
                        <ul>
                            \${result.suggestions.map(s => \`<li>\${escapeHtml(s)}</li>\`).join('')}
                        </ul>
                    </div>
                \` : '';

                document.getElementById('content').innerHTML = \`
                    <div class="explain-container">
                        <div class="section-title">SQL Query</div>
                        <div class="sql-query">\${escapeHtml(result.query)}</div>

                        <div class="section-title">Execution Plan</div>
                        <table class="explain-table">
                            <thead>
                                <tr>
                                    <th>Select Type</th>
                                    <th>Table</th>
                                    <th>Type</th>
                                    <th>Key</th>
                                    <th>Rows</th>
                                    <th>Extra</th>
                                </tr>
                            </thead>
                            <tbody>
                                \${result.plan.map(row => \`
                                    <tr>
                                        <td>\${escapeHtml(row.select_type || '')}</td>
                                        <td>\${escapeHtml(row.table || '')}</td>
                                        <td>\${escapeHtml(row.type || '')}</td>
                                        <td>\${escapeHtml(row.key || 'NULL')}</td>
                                        <td>\${escapeHtml(String(row.rows ?? ''))}</td>
                                        <td>\${escapeHtml(row.Extra || '')}</td>
                                    </tr>
                                \`).join('')}
                            </tbody>
                        </table>

                        \${warningsHtml}
                        \${suggestionsHtml}
                    </div>
                \`;
            }
            
            function showError(message) {
                document.getElementById('content').innerHTML = \`
                    <div class="warnings">
                        <div class="section-title">❌ Error</div>
                        <p>\${escapeHtml(message)}</p>
                    </div>
                \`;
            }
        </script>
    </body>
    </html>`;
  }
}
