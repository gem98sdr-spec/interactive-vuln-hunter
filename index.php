<?php
class InteractiveVulnHunter {
    private $baseDir;
    private $issues = [];
    private $stats = ['files' => 0, 'lines' => 0, 'critical' => 0, 'warning' => 0, 'info' => 0];
    private $startTime;
    private $targetPath;

    private $tokenRules = [
        'eval' => ['msg' => 'Arbitrary code execution risk (RCE).', 'level' => 'critical', 'owasp' => 'A03:Injection', 'fix' => 'Never use eval(). Refactor to safe native logic.'],
        'exec' => ['msg' => 'Command injection vulnerability.', 'level' => 'critical', 'owasp' => 'A03:Injection', 'fix' => 'Use escapeshellarg() if necessary.'],
        'shell_exec' => ['msg' => 'Command injection.', 'level' => 'critical', 'owasp' => 'A03:Injection', 'fix' => 'Avoid shell execution.'],
        'md5' => ['msg' => 'Weak cryptography.', 'level' => 'warning', 'owasp' => 'A02:Crypto Failures', 'fix' => 'Use password_hash().'],
        'var_dump' => ['msg' => 'Leftover debug function.', 'level' => 'info', 'owasp' => 'A05:Misconfiguration', 'fix' => 'Remove before production.']
    ];

    private $regexRules = [
        '/(?:password|pwd|secret)\s*=>?\s*[\'"][^\'"]{5,}[\'"]/i' => ['msg' => 'Hardcoded credentials.', 'level' => 'critical', 'owasp' => 'A07:Auth Failures', 'fix' => 'Use .env variables.'],
        '/echo\s+(?:\$_GET|\$_POST|\$_REQUEST)/i' => ['msg' => 'Direct echo (XSS).', 'level' => 'critical', 'owasp' => 'A03:Injection', 'fix' => 'Wrap in htmlspecialchars().'],
        '/(?:SELECT|UPDATE|DELETE|INSERT).*WHERE.*\$.*/i' => ['msg' => 'Potential SQL Injection.', 'level' => 'critical', 'owasp' => 'A03:Injection', 'fix' => 'Use PDO Prepared Statements.']
    ];

    public function __construct($dir) {
        $this->baseDir = rtrim($dir, DIRECTORY_SEPARATOR);
    }

    public function getTree($dir = null) {
        $dir = $dir ?: $this->baseDir;
        $items = @scandir($dir);
        $result = [];
        if (!$items) return $result;
        
        $folders = [];
        $files = [];

        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || in_array($item, ['vendor', 'node_modules', '.git'])) continue;
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            $relPath = str_replace($this->baseDir . DIRECTORY_SEPARATOR, '', $path);
            
            if (is_dir($path)) {
                $folders[] = ['type' => 'dir', 'name' => $item, 'path' => $relPath, 'children' => $this->getTree($path)];
            } elseif (pathinfo($path, PATHINFO_EXTENSION) === 'php' && $path !== __FILE__) {
                $files[] = ['type' => 'file', 'name' => $item, 'path' => $relPath];
            }
        }
        return array_merge($folders, $files);
    }

    public function scan($targetRelPath = null) {
        $this->startTime = microtime(true);
        $this->targetPath = $targetRelPath ? $this->baseDir . DIRECTORY_SEPARATOR . $targetRelPath : $this->baseDir;

        if (is_file($this->targetPath)) {
            $this->analyze($this->targetPath);
        } else {
            $this->scanDir($this->targetPath);
            if (!$targetRelPath) $this->checkExposedFiles(); 
        }

        $score = 100 - ($this->stats['critical'] * 10) - ($this->stats['warning'] * 5) - ($this->stats['info'] * 1);
        return [
            'target' => $targetRelPath ?: 'Full Project',
            'score' => max(0, $score),
            'stats' => $this->stats,
            'metrics' => ['time' => round((microtime(true) - $this->startTime) * 1000, 2)],
            'issues' => $this->issues
        ];
    }

    private function checkExposedFiles() {
        $envPath = $this->baseDir . DIRECTORY_SEPARATOR . '.env';
        if (file_exists($envPath)) {
            $this->addIssue('.env', 1, ['msg' => 'Exposed .env file.', 'level' => 'critical', 'owasp' => 'A05:Misconfiguration', 'fix' => 'Block access.'], $d, [$envPath]);
        }
    }

    private function scanDir($dir) {
        $items = @scandir($dir);
        if (!$items) return;
        foreach ($items as $item) {
            if ($item[0] === '.' || in_array($item, ['vendor', 'node_modules'])) continue;
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->scanDir($path);
            } elseif (pathinfo($path, PATHINFO_EXTENSION) === 'php' && $path !== __FILE__) {
                $this->analyze($path);
            }
        }
    }

    private function analyze($file) {
        $this->stats['files']++;
        $content = file_get_contents($file);
        $lines = explode("\n", $content);
        $this->stats['lines'] += count($lines);
        $relPath = str_replace($this->baseDir . DIRECTORY_SEPARATOR, '', $file);
        $fileIssues = 0;
        
        $tokens = token_get_all($content);
        foreach ($tokens as $token) {
            if (is_array($token)) {
                $id = $token[0]; $text = strtolower($token[1]); $line = $token[2];
                if ($id === T_EVAL) $this->addIssue($relPath, $line, $this->tokenRules['eval'], $fileIssues, $lines);
                elseif ($id === T_STRING && isset($this->tokenRules[$text])) $this->addIssue($relPath, $line, $this->tokenRules[$text], $fileIssues, $lines);
                elseif ($id === T_VARIABLE && in_array($text, ['$_get', '$_post', '$_request'])) $this->addIssue($relPath, $line, ['msg' => "Unsanitized superglobal ($text).", 'level' => 'warning', 'owasp' => 'A03:Injection', 'fix' => 'Sanitize input.'], $fileIssues, $lines);
            }
        }

        foreach ($lines as $i => $lineContent) {
            foreach ($this->regexRules as $pattern => $rule) {
                if (preg_match($pattern, $lineContent)) $this->addIssue($relPath, $i + 1, $rule, $fileIssues, $lines);
            }
        }
    }

    private function addIssue($file, $line, $rule, &$fileIssues, $lines) {
        $key = $file . '|' . $line . '|' . $rule['msg'];
        static $seen = [];
        if (isset($seen[$key])) return;
        $seen[$key] = true;
        $this->stats[$rule['level']]++;
        $fileIssues++;
        $snippet = [];
        for ($j = max(0, $line - 2); $j <= min(count($lines) - 1, $line); $j++) $snippet[$j + 1] = $lines[$j];
        $this->issues[$file][] = array_merge(['line' => $line, 'snippet' => $snippet], $rule);
    }
}

$app = new InteractiveVulnHunter(__DIR__);
$target = $_GET['scan'] ?? null;
$isScanning = isset($_GET['scan']);

if (isset($_GET['api']) && filter_var($_GET['api'], FILTER_VALIDATE_BOOLEAN)) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($isScanning ? $app->scan($target !== 'all' ? $target : null) : ['tree' => $app->getTree()]);
    exit;
}

function renderTreeUI($tree) {
    if (empty($tree)) return '';
    $html = '<ul>';
    foreach ($tree as $node) {
        if ($node['type'] === 'dir') {
            $html .= '<li class="tree-dir">
                        <div class="tree-row">
                            <span>📁 <strong>' . htmlspecialchars($node['name']) . '</strong></span>
                            <a href="?scan=' . urlencode($node['path']) . '" class="btn-scan">Scan Folder</a>
                        </div>
                        ' . renderTreeUI($node['children']) . '
                      </li>';
        } else {
            $html .= '<li class="tree-file">
                        <div class="tree-row">
                            <span>📄 ' . htmlspecialchars($node['name']) . '</span>
                            <a href="?scan=' . urlencode($node['path']) . '" class="btn-scan btn-scan-file">Scan File</a>
                        </div>
                      </li>';
        }
    }
    $html .= '</ul>';
    return $html;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive Vuln Hunter</title>
    <style>
        :root { --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#c9d1d9; --accent:#58a6ff; --critical:#f85149; --warning:#d29922; --info:#2f81f7; }
        body { font-family:system-ui,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:20px; line-height:1.6; }
        .container { max-width:1200px; margin:0 auto; }
        .header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:15px; margin-bottom:25px; }
        .header h1 { margin:0; color:var(--accent); font-size:1.8rem; }
        .btn { display:inline-block; background:var(--success, #238636); color:#fff; text-decoration:none; padding:8px 16px; border-radius:6px; font-weight:bold; }
        
        .tree-container { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:20px; }
        .tree-container ul { list-style:none; padding-left:20px; margin:5px 0; }
        .tree-container > ul { padding-left:0; }
        .tree-row { display:flex; justify-content:space-between; align-items:center; padding:8px; border-bottom:1px solid rgba(255,255,255,0.05); }
        .tree-row:hover { background:rgba(255,255,255,0.02); }
        .btn-scan { background:rgba(88,166,255,0.1); color:var(--accent); border:1px solid rgba(88,166,255,0.3); padding:4px 10px; border-radius:4px; text-decoration:none; font-size:0.8rem; }
        .btn-scan:hover { background:var(--accent); color:#fff; }
        .btn-scan-file { background:transparent; border-color:var(--border); color:#8b949e; }
        
        .dashboard { display:grid; grid-template-columns:auto 1fr; gap:20px; margin-bottom:30px; }
        @media (max-width:768px) { .dashboard { grid-template-columns:1fr; } }
        .box { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:20px; }
        .metrics-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(120px, 1fr)); gap:10px; }
        .metric { text-align:center; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:8px; padding:12px; }
        .metric .val { font-size:1.5rem; font-weight:bold; }
        .metric .label { font-size:0.75rem; color:#8b949e; text-transform:uppercase; }
        
        .file-card { background:var(--card); border:1px solid var(--border); border-radius:10px; margin-bottom:25px; }
        .file-header { background:#21262d; padding:12px 20px; border-bottom:1px solid var(--border); font-family:ui-monospace,monospace; font-weight:bold; border-radius:10px 10px 0 0; }
        .issue-item { padding:20px; border-bottom:1px solid var(--border); }
        .issue-item:last-child { border-bottom:none; }
        .badge { padding:3px 8px; border-radius:12px; font-size:0.7rem; font-weight:bold; text-transform:uppercase; margin-right:10px; }
        .badge.critical { background:var(--critical); color:#fff; }
        .badge.warning { background:var(--warning); color:#fff; }
        .badge.info { background:var(--info); color:#fff; }
        .code-snippet { background:#010409; border:1px solid var(--border); border-radius:6px; font-family:ui-monospace,monospace; font-size:0.85rem; margin-top:10px; }
        .code-line { display:flex; padding:2px 0; }
        .code-line.highlight { background:rgba(248,81,73,0.15); border-left:3px solid var(--critical); }
        .code-num { min-width:40px; padding:0 10px; color:#484f58; text-align:right; border-right:1px solid var(--border); margin-right:10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Interactive Vuln Hunter</h1>
            <a href="?" class="btn" style="background:var(--card); border:1px solid var(--border);">🏠 Home (File Explorer)</a>
        </div>

        <?php if (!$isScanning): ?>
            <div style="margin-bottom:20px; display:flex; justify-content:space-between; align-items:center;">
                <h2>Project Explorer</h2>
                <a href="?scan=all" class="btn">🚀 Scan Entire Project</a>
            </div>
            <div class="tree-container">
                <?php echo renderTreeUI($app->getTree()); ?>
            </div>
        <?php else: $report = $app->scan($target !== 'all' ? $target : null); ?>
            
            <div style="margin-bottom:20px;">
                <h2 style="margin:0;">Report for: <span style="color:var(--accent);"><?php echo htmlspecialchars($report['target']); ?></span></h2>
            </div>

            <div class="dashboard">
                <div class="box" style="text-align:center; display:flex; flex-direction:column; justify-content:center;">
                    <div style="font-size:3rem; font-weight:bold; color:<?php echo $report['score'] > 80 ? '#3fb950' : '#f85149'; ?>"><?php echo $report['score']; ?></div>
                    <div style="color:#8b949e; font-size:0.8rem; text-transform:uppercase;">Health Score</div>
                </div>
                <div class="metrics-grid">
                    <div class="metric"><div class="val"><?php echo number_format($report['stats']['files']); ?></div><div class="label">Files</div></div>
                    <div class="metric"><div class="val"><?php echo number_format($report['stats']['lines']); ?></div><div class="label">LOC</div></div>
                    <div class="metric"><div class="val" style="color:var(--critical)"><?php echo number_format($report['stats']['critical']); ?></div><div class="label">Critical</div></div>
                    <div class="metric"><div class="val" style="color:var(--warning)"><?php echo number_format($report['stats']['warning']); ?></div><div class="label">Warnings</div></div>
                    <div class="metric"><div class="val"><?php echo $report['metrics']['time']; ?></div><div class="label">ms</div></div>
                </div>
            </div>

            <?php if (empty($report['issues'])): ?>
                <div class="box" style="text-align:center; color:#3fb950; font-size:1.2rem;">
                    ✅ No vulnerabilities found in this selection.
                </div>
            <?php else: ?>
                <?php foreach ($report['issues'] as $file => $issues): ?>
                    <div class="file-card">
                        <div class="file-header">📄 <?php echo htmlspecialchars($file); ?></div>
                        <div>
                            <?php foreach ($issues as $issue): ?>
                                <div class="issue-item">
                                    <div style="margin-bottom:10px;">
                                        <span class="badge <?php echo $issue['level']; ?>"><?php echo $issue['level']; ?></span>
                                        <strong><?php echo htmlspecialchars($issue['message']); ?></strong>
                                    </div>
                                    <div class="code-snippet">
                                        <?php foreach ($issue['snippet'] as $num => $lineContent): ?>
                                            <div class="code-line <?php echo $num === $issue['line'] ? 'highlight' : ''; ?>">
                                                <div class="code-num"><?php echo $num; ?></div>
                                                <div style="color:#e6edf3; white-space:pre;"><?php echo htmlspecialchars($lineContent); ?></div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</body>
</html>
