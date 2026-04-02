import { SQLDetector, SQLDetectionResult } from "./sqlDetect";
import { AntiPatternDetector } from "./antiPatterns";
import { AntiPattern } from "./rules/ruleTypes";
import { SQLCall } from "./phpAst";

interface CacheEntry {
  version: number;
  detection: SQLDetectionResult;
  antiPatterns: Map<number, AntiPattern[]>;
}

export class AnalysisCache {
  private cache = new Map<string, CacheEntry>();
  private sqlDetector = new SQLDetector();
  private antiPatternDetector = new AntiPatternDetector();

  getDetection(uri: string, version: number, code: string): SQLDetectionResult {
    const entry = this.cache.get(uri);
    if (entry && entry.version === version) {
      return entry.detection;
    }
    const detection = this.sqlDetector.detectSQLInDocument(code);
    this.cache.set(uri, { version, detection, antiPatterns: new Map() });
    return detection;
  }

  getAntiPatterns(uri: string, version: number, code: string, query: SQLCall): AntiPattern[] {
    // Ensure detection is cached first
    this.getDetection(uri, version, code);
    const entry = this.cache.get(uri)!;
    const cached = entry.antiPatterns.get(query.line);
    if (cached) {
      return cached;
    }
    const patterns = this.antiPatternDetector.detectAntiPatterns(query);
    entry.antiPatterns.set(query.line, patterns);
    return patterns;
  }

  get detector(): SQLDetector {
    return this.sqlDetector;
  }

  updateDisabledRules(disabledRules: string[]): void {
    this.antiPatternDetector = new AntiPatternDetector(disabledRules);
    this.clear();
  }

  invalidate(uri: string): void {
    this.cache.delete(uri);
  }

  clear(): void {
    this.cache.clear();
  }
}
