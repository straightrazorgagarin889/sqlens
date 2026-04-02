import { SQLCall } from "./phpAst";

export interface TaintSource {
  type:
    | "GET" | "POST" | "REQUEST" | "COOKIE" | "SERVER" | "SESSION"
    | "FILES" | "ENV" | "INPUT_STREAM" | "GETENV" | "ARGV";
  variable: string;
  line: number;
  column: number;
}

export interface TaintSink {
  type: "SQL_QUERY";
  method: string;
  line: number;
  column: number;
  variables: string[];
}

export interface TaintFlow {
  source: TaintSource;
  sink: TaintSink;
  path: string[];
  risk: "HIGH" | "MEDIUM" | "LOW";
}

interface Assignment {
  target: string;
  sourceLine: number;
  taintedBy: string;
}

const SANITIZERS = [
  "intval",
  "floatval",
  "htmlspecialchars",
  "htmlentities",
  "addslashes",
  "mysql_real_escape_string",
  "mysqli_real_escape_string",
  "pg_escape_string",
  "escape",
  "prepare",
  "(int)",
  "(float)",
  "(bool)",
  "filter_var",
  "filter_input",
  "strip_tags",
  "password_hash",
  "password_verify",
  "is_numeric",
  "ctype_digit",
  "ctype_alpha",
  "ctype_alnum",
];

export class TaintAnalyzer {
  private sources: TaintSource[] = [];
  private sinks: TaintSink[] = [];
  private assignments: Assignment[] = [];
  private allAssignments: Array<{target: string; source: string; sourceLine: number}> = [];
  private codeLines: string[] = [];

  analyzeTaintFlow(code: string, sqlCalls: SQLCall[]): TaintFlow[] {
    this.codeLines = code.split("\n");
    this.sources = this.findTaintSources(code);
    this.sinks = this.findTaintSinks(sqlCalls);
    this.assignments = this.findAssignments(code);
    this.allAssignments = this.findAllAssignments(code);
    this.propagateTaint();

    return this.findTaintFlows(code);
  }

  private findTaintSources(_code: string): TaintSource[] {
    const sources: TaintSource[] = [];
    const lines = this.codeLines;

    lines.forEach((line, lineIndex) => {
      const patterns = [
        { pattern: /\$_GET\s*\[/g, type: "GET" as const },
        { pattern: /\$_POST\s*\[/g, type: "POST" as const },
        { pattern: /\$_REQUEST\s*\[/g, type: "REQUEST" as const },
        { pattern: /\$_COOKIE\s*\[/g, type: "COOKIE" as const },
        { pattern: /\$_SERVER\s*\[/g, type: "SERVER" as const },
        { pattern: /\$_SESSION\s*\[/g, type: "SESSION" as const },
        { pattern: /\$_FILES\s*\[/g, type: "FILES" as const },
        { pattern: /\$_ENV\s*\[/g, type: "ENV" as const },
        // Bare superglobal access without array key (e.g. $data = $_POST;)
        { pattern: /\$_GET(?!\s*\[)\b/g, type: "GET" as const },
        { pattern: /\$_POST(?!\s*\[)\b/g, type: "POST" as const },
        { pattern: /\$_REQUEST(?!\s*\[)\b/g, type: "REQUEST" as const },
        { pattern: /\$_COOKIE(?!\s*\[)\b/g, type: "COOKIE" as const },
        { pattern: /\$_SERVER(?!\s*\[)\b/g, type: "SERVER" as const },
        { pattern: /\$_SESSION(?!\s*\[)\b/g, type: "SESSION" as const },
        { pattern: /\$_FILES(?!\s*\[)\b/g, type: "FILES" as const },
        { pattern: /\$_ENV(?!\s*\[)\b/g, type: "ENV" as const },
        { pattern: /file_get_contents\s*\(\s*['"]php:\/\/input['"]/g, type: "INPUT_STREAM" as const },
        { pattern: /getenv\s*\(/g, type: "GETENV" as const },
        { pattern: /\$argv\b/g, type: "ARGV" as const },
      ];

      patterns.forEach(({ pattern, type }) => {
        let match;
        while ((match = pattern.exec(line)) !== null) {
          sources.push({
            type,
            variable: match[0],
            line: lineIndex + 1,
            column: match.index,
          });
        }
      });
    });

    return sources;
  }

  private findTaintSinks(sqlCalls: SQLCall[]): TaintSink[] {
    return sqlCalls.map((call) => ({
      type: "SQL_QUERY" as const,
      method: call.method,
      line: call.line,
      column: call.column,
      variables: call.variables || [],
    }));
  }

  private findAssignments(_code: string): Assignment[] {
    const assignments: Assignment[] = [];
    const lines = this.codeLines;

    lines.forEach((line, lineIndex) => {
      // Match $variable = $_SUPERGLOBAL[...] or $variable = expression with superglobal
      const assignmentMatch = line.match(
        /(\$\w+)\s*=\s*(.+?)(?:;|$)/
      );
      if (assignmentMatch) {
        const target = assignmentMatch[1];
        const rhs = assignmentMatch[2];

        const superGlobalPattern =
          /\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION|FILES|ENV)\s*\[/;
        const match = rhs.match(superGlobalPattern);
        if (match) {
          // Check if sanitized
          const isSanitized = SANITIZERS.some((s) => rhs.includes(s));
          if (!isSanitized) {
            assignments.push({
              target,
              sourceLine: lineIndex + 1,
              taintedBy: `$_${match[1]}`,
            });
          }
        }

        // Also match bare superglobal assignment: $data = $_POST
        if (!match) {
          const bareSuperGlobalPattern = /\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION|FILES|ENV)\s*(?:[;,)\s]|$)/;
          const bareMatch = rhs.match(bareSuperGlobalPattern);
          if (bareMatch) {
            const isSanitized = SANITIZERS.some((s) => rhs.includes(s));
            if (!isSanitized) {
              assignments.push({
                target,
                sourceLine: lineIndex + 1,
                taintedBy: `$_${bareMatch[1]}`,
              });
            }
          }
        }
      }

      // Match concatenation assignment: $var .= expression
      const concatMatch = line.match(/(\$\w+)\s*\.=\s*(.+?)(?:;|$)/);
      if (concatMatch) {
        const concatTarget = concatMatch[1];
        const concatRhs = concatMatch[2];

        const superGlobalPattern = /\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION|FILES|ENV)\s*\[/;
        const sgMatch = concatRhs.match(superGlobalPattern);
        if (sgMatch) {
          const isSanitized = SANITIZERS.some((s) => concatRhs.includes(s));
          if (!isSanitized) {
            assignments.push({
              target: concatTarget,
              sourceLine: lineIndex + 1,
              taintedBy: `$_${sgMatch[1]}`,
            });
          }
        }
      }
    });

    return assignments;
  }

  private findAllAssignments(_code: string): Array<{target: string; source: string; sourceLine: number}> {
    const allAssigns: Array<{target: string; source: string; sourceLine: number}> = [];
    const lines = this.codeLines;

    lines.forEach((line, lineIndex) => {
      // Match $target = $source or $target = $source['key'] etc.
      const assignMatch = line.match(/(\$\w+)\s*=\s*(\$\w+)/);
      if (assignMatch) {
        const target = assignMatch[1];
        const source = assignMatch[2];
        if (target !== source) {
          allAssigns.push({
            target,
            source,
            sourceLine: lineIndex + 1,
          });
        }
      }
    });

    return allAssigns;
  }

  private propagateTaint(): void {
    const taintedVars = new Set(this.assignments.map(a => a.target));
    let iterations = 0;
    const maxIterations = 10;

    let changed = true;
    while (changed && iterations < maxIterations) {
      changed = false;
      iterations++;

      for (const assign of this.allAssignments) {
        if (taintedVars.has(assign.target)) { continue; }
        if (taintedVars.has(assign.source)) {
          // Check for sanitization on the assignment line
          const line = this.codeLines[assign.sourceLine - 1] || "";
          const isSanitized = SANITIZERS.some(s => line.includes(s));
          if (!isSanitized) {
            taintedVars.add(assign.target);
            // Find the original taint source
            const originalTaint = this.assignments.find(a => a.target === assign.source);
            if (originalTaint) {
              this.assignments.push({
                target: assign.target,
                sourceLine: assign.sourceLine,
                taintedBy: originalTaint.taintedBy,
              });
            }
            changed = true;
          }
        }
      }
    }
  }

  private findTaintFlows(_code: string): TaintFlow[] {
    const flows: TaintFlow[] = [];
    const taintedVars = new Map<string, TaintSource>();

    // Build tainted variable map from direct superglobal assignments
    for (const assignment of this.assignments) {
      const matchingSource = this.sources.find(
        (s) => s.line === assignment.sourceLine
      );
      if (matchingSource) {
        taintedVars.set(assignment.target, matchingSource);
      }
    }

    // Check each sink
    for (const sink of this.sinks) {
      // Check if any sink variable is directly a superglobal
      for (const source of this.sources) {
        const sourceVarName = source.variable.replace(/\s*\[.*/, "");

        // Direct superglobal in SQL query
        if (sink.variables.some((v) => v.startsWith("$_"))) {
          const directMatch = sink.variables.find((v) =>
            v.startsWith(sourceVarName.replace("[", ""))
          );
          if (directMatch && source.line <= sink.line) {
            flows.push({
              source,
              sink,
              path: [source.variable, sink.method],
              risk: this.assessRisk(source),
            });
          }
        }
      }

      // Check if any sink variable was tainted through assignment
      for (const sinkVar of sink.variables) {
        const taintSource = taintedVars.get(sinkVar);
        if (taintSource && taintSource.line <= sink.line) {
          // Verify no sanitization between assignment and sink
          const assignmentLine = this.assignments.find(
            (a) => a.target === sinkVar
          )?.sourceLine;
          if (assignmentLine) {
            const linesBetween = this.codeLines
              .slice(assignmentLine, sink.line - 1)
              .join("\n");
            const isSanitized = SANITIZERS.some((s) =>
              linesBetween.includes(s)
            );
            if (!isSanitized) {
              flows.push({
                source: taintSource,
                sink,
                path: [taintSource.variable, sinkVar, sink.method],
                risk: this.assessRisk(taintSource),
              });
            }
          }
        }
      }

      // Fallback: proximity-based check for cases not caught above
      if (!flows.some((f) => f.sink === sink)) {
        for (const source of this.sources) {
          const lineDiff = Math.abs(sink.line - source.line);
          if (lineDiff <= 10 && source.line <= sink.line) {
            flows.push({
              source,
              sink,
              path: [source.variable, sink.method],
              risk: this.assessRisk(source),
            });
          }
        }
      }
    }

    return flows;
  }

  private assessRisk(source: TaintSource): "HIGH" | "MEDIUM" | "LOW" {
    if (["GET", "POST", "REQUEST", "FILES", "INPUT_STREAM", "ARGV"].includes(source.type)) {
      return "HIGH";
    }
    if (["COOKIE", "SERVER", "ENV", "GETENV"].includes(source.type)) {
      return "MEDIUM";
    }
    return "LOW";
  }

  isVariableTainted(variableName: string, sources: TaintSource[]): boolean {
    return sources.some(
      (source) =>
        source.variable.includes(variableName) ||
        variableName.includes(source.variable.replace(/[^a-zA-Z0-9_]/g, ""))
    );
  }
}
