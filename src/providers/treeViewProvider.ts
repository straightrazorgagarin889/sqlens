import * as vscode from "vscode";
import { SQLCall } from "../analysis/phpAst";
import { SQLDetector } from "../analysis/sqlDetect";

export class QueriesTreeProvider implements vscode.TreeDataProvider<QueryItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<
    QueryItem | undefined | null | void
  > = new vscode.EventEmitter<QueryItem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<
    QueryItem | undefined | null | void
  > = this._onDidChangeTreeData.event;

  private sqlDetector = new SQLDetector();

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: QueryItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: QueryItem): Thenable<QueryItem[]> {
    if (!element) {
      return Promise.resolve(this.getQueriesInWorkspace());
    }
    return Promise.resolve([]);
  }

  private async getQueriesInWorkspace(): Promise<QueryItem[]> {
    const items: QueryItem[] = [];

    const phpFiles = await vscode.workspace.findFiles(
      "**/*.php",
      "**/node_modules/**"
    );

    for (const file of phpFiles) {
      try {
        const document = await vscode.workspace.openTextDocument(file);
        const result = this.sqlDetector.detectSQLInDocument(document.getText());

        for (const query of result.queries) {
          const item = new QueryItem(
            this.truncateSQL(query.sql),
            query,
            file,
            vscode.TreeItemCollapsibleState.None
          );
          items.push(item);
        }
      } catch {
        // Skip files that can't be analyzed
      }
    }

    return items;
  }

  private truncateSQL(sql: string): string {
    const maxLength = 50;
    const cleaned = sql.replace(/\s+/g, " ").trim();

    if (cleaned.length <= maxLength) {
      return cleaned;
    }

    return cleaned.substring(0, maxLength) + "...";
  }
}

export class QueryItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly query: SQLCall,
    public readonly file: vscode.Uri,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState
  ) {
    super(label, collapsibleState);

    this.tooltip = this.createTooltip();
    this.description = this.createDescription();
    this.contextValue = "queryItem";
    this.iconPath = this.getIcon();

    // Command to navigate to query location
    this.command = {
      command: "vscode.open",
      title: "Open",
      arguments: [
        this.file,
        {
          selection: new vscode.Range(
            this.query.line - 1,
            this.query.column,
            this.query.line - 1,
            this.query.column + this.query.sql.length
          ),
        },
      ],
    };
  }

  private createTooltip(): string {
    const sqlType = this.query.sql.trim().split(" ")[0].toUpperCase();
    const safety = this.query.isSafe ? "Safe" : "Risky";
    const framework = this.query.framework;

    return `${sqlType} query (${safety}) - ${framework}\nLine: ${this.query.line}\n\n${this.query.sql}`;
  }

  private createDescription(): string {
    const sqlType = this.query.sql.trim().split(" ")[0].toUpperCase();
    const fileName = this.file.fsPath.split("/").pop();

    return `${sqlType} - ${fileName}:${this.query.line}`;
  }

  private getIcon(): vscode.ThemeIcon {
    const sqlType = this.query.sql.trim().split(" ")[0].toLowerCase();

    switch (sqlType) {
      case "select":
        return new vscode.ThemeIcon("search");
      case "insert":
        return new vscode.ThemeIcon("add");
      case "update":
        return new vscode.ThemeIcon("edit");
      case "delete":
        return new vscode.ThemeIcon("trash");
      default:
        return new vscode.ThemeIcon("database");
    }
  }
}
