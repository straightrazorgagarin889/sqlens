import { SQLCall } from "../phpAst";
import { AntiPattern, RuleChecker } from "./ruleTypes";
import { SecurityRuleChecker } from "./securityRules";
import { SafetyRuleChecker } from "./safetyRules";
import { PerformanceRuleChecker } from "./performanceRules";
import { CorrectnessRuleChecker } from "./correctnessRules";
import { BestPracticeRuleChecker } from "./bestPracticeRules";

export class RuleRegistry {
  private checkers: RuleChecker[] = [
    new SecurityRuleChecker(),
    new SafetyRuleChecker(),
    new PerformanceRuleChecker(),
    new CorrectnessRuleChecker(),
    new BestPracticeRuleChecker(),
  ];

  constructor(private disabledRules: string[] = []) {}

  runAll(sqlCall: SQLCall): AntiPattern[] {
    const all = this.checkers.flatMap((c) => c.check(sqlCall));
    if (this.disabledRules.length === 0) { return all; }
    return all.filter(p => !this.disabledRules.includes(p.type));
  }
}
