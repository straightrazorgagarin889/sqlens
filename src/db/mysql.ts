import * as mysql from "mysql2/promise";
import { ConfigManager } from "../utils/config";
import {
  DatabaseConnection,
  SchemaInfo,
  TableInfo,
  ColumnInfo,
  IndexInfo,
} from "./types";

export class MySQLConnection implements DatabaseConnection {
  private connection?: mysql.Connection;
  private config: ConfigManager;

  constructor() {
    this.config = new ConfigManager();
  }

  async connect(): Promise<void> {
    const dbConfig = this.config.getAll().schema;

    const timeoutMs = this.config.get<number>("preview.timeoutMs") || 2000;
    this.connection = await mysql.createConnection({
      host: dbConfig.host,
      port: dbConfig.port,
      user: dbConfig.user,
      password: dbConfig.password,
      database: dbConfig.database,
      connectTimeout: 2000,
      // Per-query timeout to prevent long-running queries
      ...(timeoutMs ? { timeout: timeoutMs } : {}),
    });
  }

  async disconnect(): Promise<void> {
    if (this.connection) {
      await this.connection.end();
      this.connection = undefined;
    }
  }

  async executeQuery(sql: string, params?: any[]): Promise<any[]> {
    if (!this.connection) {
      throw new Error("Database connection not established");
    }

    // Security: Only allow SELECT statements for preview
    const trimmedSQL = sql.trim().toLowerCase();
    if (!trimmedSQL.startsWith("select")) {
      throw new Error("Only SELECT queries are allowed for preview");
    }

    // Add LIMIT to prevent large result sets
    const rowLimit = this.config.get<number>("preview.rowLimit") || 5;
    const limitedSQL = this.addLimitToQuery(sql, rowLimit);

    const [rows] = await this.connection.execute(limitedSQL, params);
    return rows as any[];
  }

  async explainQuery(sql: string, params?: any[]): Promise<any[]> {
    if (!this.connection) {
      throw new Error("Database connection not established");
    }

    const explainSQL = `EXPLAIN ${sql}`;
    const [rows] = await this.connection.execute(explainSQL, params);
    return rows as any[];
  }

  async getSchema(): Promise<SchemaInfo> {
    if (!this.connection) {
      throw new Error("Database connection not established");
    }

    const dbConfig = this.config.getAll().schema;
    const tables = await this.getTables(dbConfig.database);
    const version = await this.getVersion();

    return {
      tables,
      version,
    };
  }

  private async getTables(database: string): Promise<TableInfo[]> {
    if (!this.connection) {
      throw new Error("Database connection not established");
    }

    const [rows] = await this.connection.execute(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = ?",
      [database]
    );

    const tables: TableInfo[] = [];

    for (const row of rows as any[]) {
      const tableName = row.table_name;
      const columns = await this.getTableColumns(database, tableName);
      const indexes = await this.getTableIndexes(database, tableName);

      tables.push({
        name: tableName,
        columns,
        indexes,
      });
    }

    return tables;
  }

  private async getTableColumns(
    database: string,
    tableName: string
  ): Promise<ColumnInfo[]> {
    if (!this.connection) {
      throw new Error("Database connection not established");
    }

    const [rows] = await this.connection.execute(
      `
      SELECT 
        column_name,
        data_type,
        is_nullable,
        column_key,
        column_default
      FROM information_schema.columns 
      WHERE table_schema = ? AND table_name = ?
      ORDER BY ordinal_position
    `,
      [database, tableName]
    );

    return (rows as any[]).map((row) => ({
      name: row.column_name,
      type: row.data_type,
      nullable: row.is_nullable === "YES",
      isPrimaryKey: row.column_key === "PRI",
      defaultValue: row.column_default,
    }));
  }

  private async getTableIndexes(
    database: string,
    tableName: string
  ): Promise<IndexInfo[]> {
    if (!this.connection) {
      throw new Error("Database connection not established");
    }

    const [rows] = await this.connection.execute(
      `
      SELECT 
        index_name,
        column_name,
        non_unique
      FROM information_schema.statistics 
      WHERE table_schema = ? AND table_name = ?
      ORDER BY index_name, seq_in_index
    `,
      [database, tableName]
    );

    const indexMap = new Map<string, IndexInfo>();

    for (const row of rows as any[]) {
      const indexName = row.index_name;

      if (!indexMap.has(indexName)) {
        indexMap.set(indexName, {
          name: indexName,
          columns: [],
          isUnique: row.non_unique === 0,
          isPrimary: indexName === "PRIMARY",
        });
      }

      indexMap.get(indexName)!.columns.push(row.column_name);
    }

    return Array.from(indexMap.values());
  }

  private async getVersion(): Promise<string> {
    if (!this.connection) {
      throw new Error("Database connection not established");
    }

    const [rows] = await this.connection.execute("SELECT VERSION() as version");
    return (rows as any[])[0].version;
  }

  private addLimitToQuery(sql: string, limit: number): string {
    // Simple LIMIT addition - in production, this would need more sophisticated SQL parsing
    const trimmed = sql.trim();

    // Check if LIMIT already exists
    if (/\bLIMIT\s+\d+/i.test(trimmed)) {
      return trimmed;
    }

    // Add LIMIT at the end
    return `${trimmed} LIMIT ${limit}`;
  }
}
