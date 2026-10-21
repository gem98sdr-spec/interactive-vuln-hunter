# Interactive Vuln Hunter 🧭🔬

Welcome to the ultimate Interactive Security Scanner for PHP. Instead of blindly scanning your entire project every time, this tool provides a **Visual Project Explorer**, allowing you to precisely target where you want to hunt for vulnerabilities.

## New Interactive Features
- **Project Explorer UI:** When loaded, it renders a beautiful directory tree of your project, excluding noise like `.git`, `vendor`, and `node_modules`.
- **Targeted Scanning:** 
  - Click **"Scan Entire Project"** for a full audit.
  - Click **"Scan Folder"** next to a specific directory (e.g., `Controllers`) to audit only that section.
  - Click **"Scan File"** next to a single PHP file for a lightning-fast micro-audit.
- **Instant Reporting:** Once a target is selected, it immediately extracts vulnerable code snippets and generates a targeted Health Score.

## Core Features Included
- **Code Snippet Extraction:** Visualizes the exact vulnerable line and surrounding code.
- **OWASP Categorization:** Identifies Injection, XSS, Crypto Failures, and more.
- **Zero Dependencies:** A single `index.php` file powered entirely by PHP's native tokenizer.

## How to Use

Drop `index.php` into the root directory of your project.

### 1. Web UI (Interactive Mode)
Simply open the file in your browser to launch the Project Explorer:
`http://your-domain.com/index.php`

### 2. JSON API
You can fetch the project tree or run targeted scans programmatically via API.

**Get Directory Tree:**
`GET /index.php?api=true`

**Scan Specific Folder (e.g., Models):**
`GET /index.php?api=true&scan=Models`

**Scan Entire Project:**
`GET /index.php?api=true&scan=all`
