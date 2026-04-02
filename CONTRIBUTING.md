# Contributing to SQLens

Thank you for your interest in contributing! Here's how you can help.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-username>/sqlens.git
   cd sqlens
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Build and watch for changes:
   ```bash
   npm run watch
   ```

## Development Workflow

### Running the Extension

1. Open the project in VS Code
2. Press **F5** to launch the Extension Development Host
3. Open a PHP file to test

### Running Tests

```bash
npm test
```

### Linting & Type Checking

```bash
npm run lint
npm run check-types
```

## Submitting Changes

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Ensure all checks pass: `npm run compile`
4. Commit with a clear message
5. Push and open a Pull Request

## Reporting Issues

- Use GitHub Issues
- Include VS Code version, extension version, and steps to reproduce
- Attach a minimal PHP file that demonstrates the problem if possible

## Code Style

- TypeScript with strict mode
- ESLint rules are enforced (see `eslint.config.mjs`)
- Follow existing patterns in the codebase

## Adding Framework Support

To add a new PHP framework:

1. Add detection patterns in `src/analysis/phpAst.ts`
2. Add the framework key to the `frameworks` config in `package.json`
3. Add test cases in `src/test/phpAst.test.ts`
4. Add integration examples in `test-project/`

## Adding Analysis Rules

Rules live in `src/analysis/rules/`. Each category has its own file:

- `securityRules.ts` - SQL injection, unsafe functions
- `safetyRules.ts` - Destructive operations without guards
- `performanceRules.ts` - Query optimization issues
- `correctnessRules.ts` - SQL semantic errors
- `bestPracticeRules.ts` - Code quality recommendations

Add the rule type to `ruleTypes.ts`, implement the check, and add tests.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
