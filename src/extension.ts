import * as vscode from "vscode";
import { HoverProvider } from "./providers/hoverProvider";
import { CodeLensProvider } from "./providers/codeLensProvider";
import { DiagnosticsProvider } from "./providers/diagnosticsProvider";
import { QueriesTreeProvider } from "./providers/treeViewProvider";
import { ExplainWebviewProvider } from "./ui/explainWebview";
import { ConfigManager } from "./utils/config";
import { SQLDetector } from "./analysis/sqlDetect";
import { AntiPatternDetector } from "./analysis/antiPatterns";
import { AnalysisCache } from "./analysis/analysisCache";
import { SQLCall } from "./analysis/phpAst";
import { DatabaseConnection } from "./db/types";
import { MySQLConnection } from "./db/mysql";
import { PostgreSQLConnection } from "./db/pg";
import { QuickFixProvider } from "./providers/codeActionProvider";

function buildSQLCallFromInfo(info: any): SQLCall {
  return {
    sql: info.sql ?? "",
    line: info.line ?? 0,
    column: info.column ?? 0,
    framework: info.framework ?? "unknown",
    method: info.method ?? "query",
    hasBinding: info.hasBinding ?? false,
    isSafe: info.isSafe ?? true,
    variables: info.variables ?? [],
    enclosingLoop: info.enclosingLoop ?? false,
    loopType: info.loopType ?? null,
    surroundingCode: info.surroundingCode ?? "",
    usesSprintfInterpolation: info.usesSprintfInterpolation ?? false,
  };
}

// Reusable output channels (avoid creating new ones on every call)
let previewOutputChannel: vscode.OutputChannel | undefined;
let safetyOutputChannel: vscode.OutputChannel | undefined;

function getPreviewOutputChannel(): vscode.OutputChannel {
  if (!previewOutputChannel) {
    previewOutputChannel = vscode.window.createOutputChannel("SQLens");
  }
  return previewOutputChannel;
}

function getSafetyOutputChannel(): vscode.OutputChannel {
  if (!safetyOutputChannel) {
    safetyOutputChannel = vscode.window.createOutputChannel("SQLens - Safety");
  }
  return safetyOutputChannel;
}

// Debounce support
const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

function debounce(key: string, fn: () => void, delayMs: number): void {
  const existing = debounceTimers.get(key);
  if (existing) {
    clearTimeout(existing);
  }
  debounceTimers.set(key, setTimeout(() => {
    debounceTimers.delete(key);
    fn();
  }, delayMs));
}

export function activate(context: vscode.ExtensionContext) {
  const config = new ConfigManager();

  if (!config.get<boolean>("enable")) {
    return;
  }

  // Shared analysis cache
  const analysisCache = new AnalysisCache();

  // Read disabled rules from configuration
  const vsConfig = vscode.workspace.getConfiguration("sqlens");
  const disabledRules = vsConfig.get<string[]>("disabledRules", []);
  if (disabledRules.length > 0) {
    analysisCache.updateDisabledRules(disabledRules);
  }

  // Create providers with shared cache
  const hoverProvider = new HoverProvider(analysisCache);
  const codeLensProvider = new CodeLensProvider(analysisCache);
  const diagnosticsProvider = new DiagnosticsProvider(analysisCache);
  const queriesTreeProvider = new QueriesTreeProvider();
  const explainWebviewProvider = new ExplainWebviewProvider(context);

  // Register providers
  context.subscriptions.push(
    vscode.languages.registerHoverProvider({ language: "php" }, hoverProvider),
    vscode.languages.registerCodeLensProvider(
      { language: "php" },
      codeLensProvider
    ),
    vscode.window.registerTreeDataProvider(
      "sqlensQueriesView",
      queriesTreeProvider
    ),
    vscode.window.registerWebviewViewProvider(
      "sqlensExplainView",
      explainWebviewProvider
    ),
    { dispose: () => diagnosticsProvider.dispose() }
  );

  // Register CodeAction provider for quick fixes
  const quickFixProvider = new QuickFixProvider(analysisCache);
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { language: "php" },
      quickFixProvider,
      { providedCodeActionKinds: QuickFixProvider.providedCodeActionKinds }
    )
  );

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "sqlens.previewQuery",
      async (sql: string) => {
        if (config.get("preview.enabled")) {
          await previewQuery(sql);
        } else {
          await staticPreviewQuery(sql);
        }
      }
    ),
    vscode.commands.registerCommand(
      "sqlens.explainQuery",
      async (sql: string) => {
        if (config.get("preview.enabled")) {
          await explainQuery(sql, explainWebviewProvider);
        } else {
          await staticExplainQuery(sql, explainWebviewProvider);
        }
      }
    ),
    vscode.commands.registerCommand("sqlens.copyQuery", async (sql: string) => {
      await vscode.env.clipboard.writeText(sql);
      vscode.window.showInformationMessage("SQL query copied to clipboard");
    }),
    vscode.commands.registerCommand("sqlens.refreshQueries", () => {
      analysisCache.clear();
      queriesTreeProvider.refresh();
    }),
    vscode.commands.registerCommand("sqlens.showSafetyInfo", (queryInfo: any) => {
      if (!queryInfo) {
        vscode.window.showWarningMessage("No query information available.");
        return;
      }

      const detector = analysisCache.detector;
      const queryType = detector.extractSQLType(queryInfo.sql || "");
      const tables = detector.extractTables(queryInfo.sql || "");
      const columns = detector.extractColumns(queryInfo.sql || "");

      const sqlCall = buildSQLCallFromInfo(queryInfo);
      const antiPatternDetector = new AntiPatternDetector(disabledRules);
      const antiPatterns = antiPatternDetector.detectAntiPatterns(sqlCall);

      const hasErrors = antiPatterns.some((ap) => ap.severity === "error");
      const hasWarnings = antiPatterns.some((ap) => ap.severity === "warning");
      const overallStatus = hasErrors ? "ERROR" : hasWarnings ? "WARNING" : queryInfo.isSafe ? "SAFE" : "RISKY";

      const userVars = (queryInfo.variables || []).filter(
        (v: string) => v !== "$this" && v !== "$self"
      );

      const output = getSafetyOutputChannel();
      output.clear();
      output.appendLine("-- Security Analysis --\n");
      output.appendLine(`SQL: ${queryInfo.sql}\n`);
      output.appendLine(`Status:     ${overallStatus}`);
      output.appendLine(`Framework:  ${queryInfo.framework || "unknown"}`);
      output.appendLine(`Method:     ${queryInfo.method ? queryInfo.method + "()" : "unknown"}`);
      output.appendLine(`Query Type: ${queryType}`);
      output.appendLine(`Tables:     ${tables.length > 0 ? tables.join(", ") : "(could not detect)"}`);
      if (queryType === "SELECT") {
        output.appendLine(`Columns:    ${columns.length > 0 ? columns.join(", ") : "(could not detect)"}`);
      }
      output.appendLine(`Binding:    ${queryInfo.hasBinding ? "Yes" : "No"}`);

      if (userVars.length > 0) {
        output.appendLine(`\n-- Variables --`);
        for (const v of userVars) {
          output.appendLine(`  ${v}`);
        }
      }

      if (antiPatterns.length > 0) {
        output.appendLine("\n-- Issues --");
        for (const ap of antiPatterns) {
          const icon = ap.severity === "error" ? "[ERROR]" : ap.severity === "warning" ? "[WARN]" : "[INFO]";
          output.appendLine(`${icon} ${ap.message}`);
          if (ap.suggestion) {
            output.appendLine(`       -> ${ap.suggestion}`);
          }
        }
      } else {
        output.appendLine("\n-- Issues --");
        output.appendLine("[OK] No issues detected.");
      }

      output.show(true);
    }),

    vscode.commands.registerCommand("sqlens.testExtension", () => {
      const detector = new SQLDetector();

      const activeEditor = vscode.window.activeTextEditor;
      if (activeEditor && activeEditor.document.languageId === "php") {
        const result = detector.detectSQLInDocument(
          activeEditor.document.getText()
        );
        vscode.window.showInformationMessage(
          `Found ${result.totalQueries} SQL queries in current file!`
        );
        diagnosticsProvider.updateDiagnostics(activeEditor.document);
        queriesTreeProvider.refresh();
      } else {
        vscode.window.showWarningMessage(
          "Please open a PHP file to test SQL detection"
        );
      }

      const openPhpDocs = vscode.workspace.textDocuments.filter(
        (doc) => doc.languageId === "php"
      );

      let totalQueries = 0;
      openPhpDocs.forEach((doc) => {
        const result = detector.detectSQLInDocument(doc.getText());
        totalQueries += result.totalQueries;
        diagnosticsProvider.updateDiagnostics(doc);
      });

      vscode.window.showInformationMessage(
        `Total: ${totalQueries} SQL queries found across all open PHP files!`
      );
    }),

    vscode.commands.registerCommand("sqlens.resetExtension", () => {
      vscode.window.showInformationMessage("Resetting SQLens...");

      analysisCache.clear();

      const openPhpDocs = vscode.workspace.textDocuments.filter(
        (doc) => doc.languageId === "php"
      );

      openPhpDocs.forEach((doc) => {
        diagnosticsProvider.updateDiagnostics(doc);
      });

      queriesTreeProvider.refresh();
      vscode.window.showInformationMessage(
        "Reset complete! All PHP files re-analyzed."
      );
    })
  );

  // Watch for document changes (debounced)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.languageId === "php") {
        debounce(e.document.uri.toString(), () => {
          diagnosticsProvider.updateDiagnostics(e.document);
          queriesTreeProvider.refresh();
        }, 300);
      }
    })
  );

  // Watch for document opens
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document) => {
      if (document.languageId === "php") {
        diagnosticsProvider.updateDiagnostics(document);
        queriesTreeProvider.refresh();
      }
    })
  );

  // Watch for active editor changes
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && editor.document.languageId === "php") {
        diagnosticsProvider.updateDiagnostics(editor.document);
        queriesTreeProvider.refresh();
      }
    })
  );

  // Watch for configuration changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("sqlens.disabledRules")) {
        const newDisabled = vscode.workspace.getConfiguration("sqlens")
          .get<string[]>("disabledRules", []);
        analysisCache.updateDisabledRules(newDisabled);
        // Re-analyze all open PHP files
        vscode.workspace.textDocuments
          .filter((doc) => doc.languageId === "php")
          .forEach((doc) => diagnosticsProvider.updateDiagnostics(doc));
      }
    })
  );

  // Initial analysis of open PHP files
  vscode.workspace.textDocuments
    .filter((doc) => doc.languageId === "php")
    .forEach((doc) => {
      diagnosticsProvider.updateDiagnostics(doc);
    });
}

function createDbConnection(config: ConfigManager): DatabaseConnection {
  const driver = config.get<string>("schema.driver");
  if (driver === "postgresql") {
    return new PostgreSQLConnection();
  }
  return new MySQLConnection();
}

async function previewQuery(sql: string) {
  const config = new ConfigManager();
  const db = createDbConnection(config);

  try {
    await db.connect();
    const rows = await db.executeQuery(sql);

    const output = getPreviewOutputChannel();
    output.clear();
    output.appendLine(`-- Query Preview --`);
    output.appendLine(sql);
    output.appendLine(`\n-- Results (${rows.length} rows) --`);

    if (rows.length > 0) {
      const columns = Object.keys(rows[0]);
      output.appendLine(columns.join("\t"));
      output.appendLine("-".repeat(columns.length * 15));
      for (const row of rows) {
        output.appendLine(columns.map((col) => String(row[col] ?? "NULL")).join("\t"));
      }
    } else {
      output.appendLine("(no results)");
    }

    output.show(true);
  } catch (error) {
    vscode.window.showErrorMessage(
      `Preview failed: ${error instanceof Error ? error.message : error}`
    );
  } finally {
    await db.disconnect();
  }
}

async function explainQuery(
  sql: string,
  webviewProvider: ExplainWebviewProvider
) {
  const config = new ConfigManager();
  const db = createDbConnection(config);

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

    webviewProvider.showExplainResult({
      query: sql,
      plan,
      warnings,
      suggestions,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("connection") || message.includes("ECONNREFUSED")) {
      vscode.window.showWarningMessage(
        "Database connection not configured. Configure it in Settings > SQLens."
      );
    } else {
      vscode.window.showErrorMessage(`Explain failed: ${message}`);
    }
    webviewProvider.showExplainPlan(sql);
  } finally {
    await db.disconnect();
  }
}

async function staticPreviewQuery(sql: string) {
  const detector = new SQLDetector();
  const antiPatternDetector = new AntiPatternDetector();

  const queryType = detector.extractSQLType(sql);
  const tables = detector.extractTables(sql);
  const columns = detector.extractColumns(sql);

  const antiPatterns = antiPatternDetector.detectAntiPatterns(
    buildSQLCallFromInfo({ sql })
  );

  const output = getPreviewOutputChannel();
  output.clear();
  output.appendLine("-- Query Analysis (Static) --\n");
  output.appendLine(`SQL: ${sql}\n`);
  output.appendLine(`Type:    ${queryType}`);
  output.appendLine(`Tables:  ${tables.length > 0 ? tables.join(", ") : "(could not detect)"}`);

  if (queryType === "SELECT") {
    output.appendLine(`Columns: ${columns.length > 0 ? columns.join(", ") : "(could not detect)"}`);
  }

  if (antiPatterns.length > 0) {
    output.appendLine("\n-- Issues --");
    for (const ap of antiPatterns) {
      const icon = ap.severity === "error" ? "[ERROR]" : ap.severity === "warning" ? "[WARN]" : "[INFO]";
      output.appendLine(`${icon} ${ap.message}`);
      if (ap.suggestion) {
        output.appendLine(`      -> ${ap.suggestion}`);
      }
    }
  } else {
    output.appendLine("\nNo issues detected.");
  }

  output.appendLine("\n-- Tip --");
  output.appendLine("Enable database connection in settings for live query preview.");
  output.show(true);
}

async function staticExplainQuery(
  sql: string,
  webviewProvider: ExplainWebviewProvider
) {
  const detector = new SQLDetector();
  const antiPatternDetector = new AntiPatternDetector();

  const queryType = detector.extractSQLType(sql);
  const tables = detector.extractTables(sql);
  const columns = detector.extractColumns(sql);

  const antiPatterns = antiPatternDetector.detectAntiPatterns(
    buildSQLCallFromInfo({ sql })
  );

  const warnings: string[] = [];
  const suggestions: string[] = [];

  for (const ap of antiPatterns) {
    warnings.push(ap.message);
    if (ap.suggestion) {
      suggestions.push(ap.suggestion);
    }
  }

  // Build a static plan from SQL parsing
  const plan: Record<string, string>[] = tables.map((table) => ({
    select_type: queryType === "SELECT" ? "SIMPLE" : "-",
    table,
    type: "(static analysis)",
    key: "(requires DB)",
    rows: "(requires DB)",
    Extra: columns.includes("*") ? "Using SELECT *" : "",
  }));

  if (plan.length === 0) {
    plan.push({
      select_type: queryType,
      table: "(could not detect)",
      type: "(static analysis)",
      key: "(requires DB)",
      rows: "(requires DB)",
      Extra: "Enable DB connection for full EXPLAIN plan",
    });
  }

  if (!warnings.length && !suggestions.length) {
    suggestions.push("Enable database connection in settings for a full EXPLAIN plan.");
  }

  webviewProvider.showExplainResult({ query: sql, plan, warnings, suggestions });
}

export function deactivate() {
  for (const timer of debounceTimers.values()) {
    clearTimeout(timer);
  }
  debounceTimers.clear();
  previewOutputChannel?.dispose();
  safetyOutputChannel?.dispose();
  previewOutputChannel = undefined;
  safetyOutputChannel = undefined;
}
