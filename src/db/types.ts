export interface DatabaseConnection {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  executeQuery(sql: string, params?: any[]): Promise<any[]>;
  explainQuery(sql: string, params?: any[]): Promise<any[]>;
  getSchema(): Promise<SchemaInfo>;
}

export interface SchemaInfo {
  tables: TableInfo[];
  version: string;
}

export interface TableInfo {
  name: string;
  columns: ColumnInfo[];
  indexes: IndexInfo[];
}

export interface ColumnInfo {
  name: string;
  type: string;
  nullable: boolean;
  isPrimaryKey: boolean;
  defaultValue?: string;
}

export interface IndexInfo {
  name: string;
  columns: string[];
  isUnique: boolean;
  isPrimary: boolean;
}
