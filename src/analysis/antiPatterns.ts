import { SQLCall } from "./phpAst";
import { AntiPattern } from "./rules/ruleTypes";
import { RuleRegistry } from "./rules/index";

export type { AntiPattern } from "./rules/ruleTypes";

export class AntiPatternDetector {
  private registry: RuleRegistry;

  constructor(disabledRules: string[] = []) {
    this.registry = new RuleRegistry(disabledRules);
  }

  detectAntiPatterns(sqlCall: SQLCall): AntiPattern[] {
    return this.registry.runAll(sqlCall);
  }
}
