import { SQLDetector } from "../src/analysis/sqlDetect";
import { AntiPatternDetector } from "../src/analysis/antiPatterns";
import { TaintAnalyzer } from "../src/analysis/taint";
import * as fs from "fs";
import * as path from "path";

const detector = new SQLDetector();
const antiDetector = new AntiPatternDetector();
const taintAnalyzer = new TaintAnalyzer();

const testDir = path.join(process.cwd(), "test-project");
const files = fs.readdirSync(testDir).filter((f) => f.endsWith(".php"));

let totalQueries = 0;
let totalSafe = 0;
let totalRisky = 0;
let totalAntiPatterns = 0;
let totalTaintFlows = 0;

files.forEach((file) => {
  const code = fs.readFileSync(path.join(testDir, file), "utf-8");
  const result = detector.detectSQLInDocument(code);

  let antiPatternCount = 0;
  result.queries.forEach((q) => {
    antiPatternCount += antiDetector.detectAntiPatterns(q).length;
  });

  const flows = taintAnalyzer.analyzeTaintFlow(code, result.queries);

  console.log(`${file}:`);
  console.log(`  Queries: ${result.totalQueries} (safe: ${result.safeQueries}, risky: ${result.riskyQueries})`);
  console.log(`  Anti-patterns: ${antiPatternCount}`);
  console.log(`  Taint flows: ${flows.length}`);

  totalQueries += result.totalQueries;
  totalSafe += result.safeQueries;
  totalRisky += result.riskyQueries;
  totalAntiPatterns += antiPatternCount;
  totalTaintFlows += flows.length;
});

console.log("\n=== TOPLAM ===");
console.log(`Toplam sorgu: ${totalQueries}`);
console.log(`Guvenli: ${totalSafe}`);
console.log(`Riskli: ${totalRisky}`);
console.log(`Anti-pattern: ${totalAntiPatterns}`);
console.log(`Taint flow: ${totalTaintFlows}`);

if (totalQueries === 0) {
  console.error("\nHATA: Hic sorgu tespit edilemedi!");
  process.exit(1);
}

console.log("\nSONUC: Tum dosyalar basariyla analiz edildi.");
