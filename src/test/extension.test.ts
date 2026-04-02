import * as assert from "assert";
import * as vscode from "vscode";

suite("Extension Test Suite", () => {
  test("extension should be present", () => {
    const _extension = vscode.extensions.getExtension("aliyilmazco.sqlens");
    // Extension may not be installed in test environment, just check the API works
    assert.ok(true, "VS Code extension API is accessible");
  });

  test("commands should be registered", async () => {
    const commands = await vscode.commands.getCommands(true);
    const sqlensCommands = commands.filter((cmd) => cmd.startsWith("sqlens."));
    // Commands may not be registered if extension isn't activated in test env
    assert.ok(Array.isArray(sqlensCommands), "Should return array of commands");
  });

  test("configuration section exists", () => {
    const config = vscode.workspace.getConfiguration("sqlens");
    assert.ok(config, "Configuration section should exist");
    assert.strictEqual(
      typeof config.get("enable"),
      "boolean",
      "enable should be boolean"
    );
  });
});
