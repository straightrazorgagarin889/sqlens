import { Client } from "pg";
import { ConfigManager } from "../utils/config";
import {
  DatabaseConnection,
  SchemaInfo,
  TableInfo,
  ColumnInfo,
  IndexInfo,
} from "./types";

export class PostgreSQLConnection implements DatabaseConnection {
  private client?: Client;
  private config: ConfigManager;

  constructor() {
    this.config = new ConfigManager();
  }

  async connect(): Promise<void> {
    const dbConfig = this.config.getAll().schema;

    this.client = new Client({
      host: dbConfig.host,
      port: dbConfig.port,
      user: dbConfig.user,
      password: dbConfig.password,
      database: dbConfig.database,
      connectionTimeoutMillis: 2000,
      query_timeout: this.config.get("preview.timeoutMs") || 2000,
    });

    await this.client.connect();
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.end();
      this.client = undefined;
    }
  }

  async executeQuery(sql: string, params?: any[]): Promise<any[]> {
    if (!this.client) {
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

    const result = await this.client.query(limitedSQL, params);
    return result.rows;
  }

  async explainQuery(sql: string, params?: any[]): Promise<any[]> {
    if (!this.client) {
      throw new Error("Database connection not established");
    }

    const explainSQL = `EXPLAIN (FORMAT JSON, ANALYZE) ${sql}`;
    const result = await this.client.query(explainSQL, params);
    return result.rows;
  }

  async getSchema(): Promise<SchemaInfo> {
    if (!this.client) {
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

  private async getTables(_database: string): Promise<TableInfo[]> {
    if (!this.client) {
      throw new Error("Database connection not established");
    }

    const result = await this.client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_type = 'BASE TABLE'
    `);

    const tables: TableInfo[] = [];

    for (const row of result.rows) {
      const tableName = row.table_name;
      const columns = await this.getTableColumns(tableName);
      const indexes = await this.getTableIndexes(tableName);

      tables.push({
        name: tableName,
        columns,
        indexes,
      });
    }

    return tables;
  }

  private async getTableColumns(tableName: string): Promise<ColumnInfo[]> {
    if (!this.client) {
      throw new Error("Database connection not established");
    }

    // Get primary key columns
    const pkResult = await this.client.query(
      `
      SELECT a.attname
      FROM pg_index i
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
      WHERE i.indrelid = $1::regclass AND i.indisprimary
    `,
      [tableName]
    );
    const pkColumns = new Set(pkResult.rows.map((r) => r.attname));

    const result = await this.client.query(
      `
      SELECT
        column_name,
        data_type,
        is_nullable,
        column_default
      FROM information_schema.columns
      WHERE table_name = $1
      ORDER BY ordinal_position
    `,
      [tableName]
    );

    return result.rows.map((row) => ({
      name: row.column_name,
      type: row.data_type,
      nullable: row.is_nullable === "YES",
      isPrimaryKey: pkColumns.has(row.column_name),
      defaultValue: row.column_default,
    }));
  }

  private async getTableIndexes(tableName: string): Promise<IndexInfo[]> {
    if (!this.client) {
      throw new Error("Database connection not established");
    }

    const result = await this.client.query(
      `
      SELECT 
        i.relname as index_name,
        a.attname as column_name,
        ix.indisunique as is_unique,
        ix.indisprimary as is_primary
      FROM 
        pg_class t,
        pg_class i,
        pg_index ix,
        pg_attribute a
      WHERE 
        t.oid = ix.indrelid
        AND i.oid = ix.indexrelid
        AND a.attrelid = t.oid
        AND a.attnum = ANY(ix.indkey)
        AND t.relkind = 'r'
        AND t.relname = $1
      ORDER BY i.relname, a.attname
    `,
      [tableName]
    );

    const indexMap = new Map<string, IndexInfo>();

    for (const row of result.rows) {
      const indexName = row.index_name;

      if (!indexMap.has(indexName)) {
        indexMap.set(indexName, {
          name: indexName,
          columns: [],
          isUnique: row.is_unique,
          isPrimary: row.is_primary,
        });
      }

      indexMap.get(indexName)!.columns.push(row.column_name);
    }

    return Array.from(indexMap.values());
  }

  private async getVersion(): Promise<string> {
    if (!this.client) {
      throw new Error("Database connection not established");
    }

    const result = await this.client.query("SELECT version()");
    return result.rows[0].version;
  }

  private addLimitToQuery(sql: string, limit: number): string {
    // Simple LIMIT addition for PostgreSQL
    const trimmed = sql.trim();

    // Check if LIMIT already exists
    if (/\bLIMIT\s+\d+/i.test(trimmed)) {
      return trimmed;
    }

    // Add LIMIT at the end
    return `${trimmed} LIMIT ${limit}`;
  }
}
