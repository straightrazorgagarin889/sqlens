import * as vscode from "vscode";

export interface SQLensConfig {
  enable: boolean;
  frameworks: string[];
  schema: {
    autoDiscover: boolean;
    driver: "mysql" | "postgresql";
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
  };
  preview: {
    enabled: boolean;
    rowLimit: number;
    timeoutMs: number;
    allowNonSelect: boolean;
  };
}

export class ConfigManager {
  private readonly configSection = "sqlens";

  get<T>(key: string): T {
    const config = vscode.workspace.getConfiguration(this.configSection);
    return config.get<T>(key) as T;
  }

  getAll(): SQLensConfig {
    const config = vscode.workspace.getConfiguration(this.configSection);
    return {
      enable: config.get("enable", true),
      frameworks: config.get("frameworks", [
        "pdo",
        "mysqli",
        "wordpress",
        "ezsql",
        "laravel-db",
        "doctrine",
      ]),
      schema: {
        autoDiscover: config.get("schema.autoDiscover", false),
        driver: config.get("schema.driver", "mysql"),
        host: config.get("schema.host", "127.0.0.1"),
        port: config.get("schema.port", 3306),
        database: config.get("schema.database", "app_db"),
        user: config.get("schema.user", "readonly"),
        password: config.get("schema.password", ""),
      },
      preview: {
        enabled: config.get("preview.enabled", false),
        rowLimit: config.get("preview.rowLimit", 5),
        timeoutMs: config.get("preview.timeoutMs", 2000),
        allowNonSelect: config.get("preview.allowNonSelect", false),
      },
    };
  }

  async update(
    key: string,
    value: any,
    target?: vscode.ConfigurationTarget
  ): Promise<void> {
    const config = vscode.workspace.getConfiguration(this.configSection);
    await config.update(key, value, target);
  }
}
