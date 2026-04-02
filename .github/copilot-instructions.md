<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization #_use-a-githubcopilotinstructionsmd-file -->

## 🎯 Current Task: Enhanced ezSQL Support & Testing

### PRIORITY: ezSQL Framework Integration

- [x] Enhance ezSQL Detection Patterns
<!-- Add comprehensive ezSQL method detection in phpAst.ts --> ✅ Enhanced detection with 15+ methods
- [x] ezSQL Security Analysis
<!-- Implement ezSQL-specific security patterns and vulnerabilities --> ✅ Added escape validation, user input detection
- [x] ezSQL Performance Optimization
<!-- Add ezSQL-specific performance recommendations --> ✅ Added cache bypass, performance patterns
- [x] ezSQL Hover Provider Enhancement
<!-- Improve hover information for ezSQL methods --> ✅ Comprehensive method info, tips, security alerts
- [x] ezSQL CodeLens Actions
<!-- Add ezSQL-specific CodeLens functionality --> ✅ Works with existing CodeLens provider
- [x] ezSQL Test Examples
<!-- Create comprehensive ezSQL test cases --> ✅ 50+ test cases with safe/risky patterns
- [x] Local Testing & Debugging
<!-- Set up local testing environment and run extension --> ✅ Ready to test with comprehensive guide!

### 🧪 Testing Instructions:

#### 1. Launch Extension in Debug Mode:

```bash
# In VS Code workspace root:
# 1. Press F5 to start Extension Development Host
# 2. New VS Code window will open with extension loaded
# 3. Open the test-examples.php file in the new window
```

#### 2. Test ezSQL Features:

- **Hover Testing**: Hover over ezSQL queries to see enhanced information
- **CodeLens Testing**: Look for Preview/Explain/Copy/Safety buttons above queries
- **Diagnostics Testing**: Check Problems panel for ezSQL-specific warnings
- **Tree View Testing**: Open "SQL Queries" panel in Explorer to see all detected queries

#### 3. Expected ezSQL Behaviors:

- ✅ **Detection**: All ezSQL methods should be detected (get_results, get_row, etc.)
- ✅ **Security**: Risky queries should show warnings/errors
- ✅ **Performance**: SELECT \*, cache bypass, OR explosion warnings
- ✅ **Method Info**: Hover should show ezSQL-specific documentation
- ✅ **Anti-patterns**: ezSQL-specific issues should be flagged

#### 4. Debug Commands:

```bash
# If changes made, rebuild:
npm run compile

# Reload extension in Development Host:
Ctrl+Shift+F5 (or Cmd+Shift+F5 on Mac)
```

#### 5. Validation Checklist:

- [ ] Extension loads without errors
- [ ] ezSQL queries detected in test-examples.php
- [ ] Hover shows ezSQL-specific information
- [ ] CodeLens buttons appear on SQL lines
- [ ] Problems panel shows security/performance warnings
- [ ] Tree view lists all detected queries
- [ ] No TypeScript compilation errors

### ezSQL Framework Specifics to Implement:

#### Core ezSQL Methods:

- `get_results()` - Multiple row results
- `get_row()` - Single row result
- `get_var()` - Single variable result
- `get_col()` - Single column results
- `query()` - Direct query execution
- `prepare()` - Prepared statements (if supported)
- `escape()` - String escaping
- `insert()` - Insert operations
- `update()` - Update operations
- `delete()` - Delete operations

#### ezSQL Security Patterns:

- Escape function usage validation
- Direct variable interpolation detection
- ezSQL cache bypass detection
- Error handling pattern analysis

#### ezSQL Performance Patterns:

- Cache utilization checking
- Query optimization recommendations
- Batch operation suggestions
- Connection pooling analysis

### Implementation Guidelines:

1. **Focus on ezSQL ecosystem compatibility**
2. **Maintain backward compatibility with existing frameworks**
3. **Add ezSQL-specific error patterns and solutions**
4. **Create realistic test scenarios for ezSQL**
5. **Ensure proper local testing setup**

### Testing Requirements:

- Extension must load without errors in Development Host
- ezSQL queries must be properly detected and analyzed
- All providers (Hover, CodeLens, Diagnostics, TreeView) must work with ezSQL
- Test with real ezSQL code examples
- Verify performance and security analysis accuracy

---

## ✅ Completed Tasks:

- [x] Verify that the copilot-instructions.md file in the .github directory is created. ✅ Created

- [x] Clarify Project Requirements
<!-- SQLens VS Code extension with TypeScript, SQL detection, hover provider, CodeLens, diagnostics --> ✅ Requirements clarified

- [x] Scaffold the Project
<!-- VS Code extension project with TypeScript setup --> ✅ Scaffolded with Yeoman

- [x] Customize the Project
<!-- Implement PHP AST parsing, SQL detection, providers, and database connections --> ✅ All core modules implemented

- [x] Install Required Extensions
<!-- Install VS Code extension development dependencies --> ✅ Dependencies installed

- [x] Compile the Project
<!-- Build TypeScript and resolve dependencies --> ✅ Compiled successfully

- [x] Create and Run Task
<!-- Create build and test tasks --> ✅ Build tasks ready

- [x] Launch the Project
<!-- Extension debugging in Extension Development Host --> ✅ Ready to launch with F5

- [x] Ensure Documentation is Complete
<!-- Complete README.md and documentation --> ✅ Comprehensive documentation created
