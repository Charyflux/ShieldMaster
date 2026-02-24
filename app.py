import os
import subprocess
import shutil
import re
import json
import shlex
from flask import Flask, render_template, request, jsonify
from werkzeug.security import safe_join

app = Flask(__name__)
# Configuração de diretórios e segurança
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
TEMP_DIR = os.path.join(os.getcwd(), ".audit_final_v1")

# Mensagens de Risco para o Dashboard
RISK_LEVELS = {
    "CRITICAL": "💀 CRÍTICO: Exposição de segredos. Acesso total imediato!",
    "HIGH": "🔥 ALTO: Vulnerabilidade de injeção ou lógica detectada.",
    "MEDIUM": "⚠️ MÉDIO: Prática insegura ou má configuração."
}

def install_tools():
    print("🚀 [SHIELD MASTER] Blindando ambiente e instalando motores...")
    subprocess.run(["pip", "install", "semgrep", "--break-system-packages", "--quiet"])
    if not shutil.which("trufflehog"):
        subprocess.run("curl -sSfL https://raw.githubusercontent.com/trufflehog/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin", shell=True)

def is_safe_url(url):
    # REGEX Red Team: Valida se a URL é puramente GitHub para evitar Command Injection
    pattern = re.compile(r'^https://github\.com/[a-zA-Z0-9\-_.]+/[a-zA-Z0-9\-_.]+(?:\.git)?$')
    return pattern.match(url)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def run_scan():
    url = request.form.get('repo_url', '').strip()
    token = request.form.get('github_token', '').strip()
    target = os.path.join(TEMP_DIR, "clone")
    
    if not is_safe_url(url):
        return jsonify({"error": "URL do GitHub inválida ou maliciosa detectada."}), 400

    try:
        if os.path.exists(TEMP_DIR): shutil.rmtree(TEMP_DIR)
        os.makedirs(target)
        
        # Extração segura da identidade do repositório
        repo_path_match = re.search(r'github\.com/([^/]+/[^/]+)', url.replace(".git", ""))
        if not repo_path_match:
            return jsonify({"error": "Caminho do repositório não identificado."}), 400
        
        repo_identity = repo_path_match.group(1)

        # ARRUMANDO A VULNERABILIDADE (Linha 38): Parametrização ao invés de F-String direta
        if token:
            # shlex.quote limpa o token contra injeções
            clean_token = shlex.quote(token)
            clone_url = f"https://{clean_token}@github.com/{repo_identity}.git"
        else:
            clone_url = f"https://github.com/{repo_identity}.git"
            
        # Execução via lista (Ouro da Segurança): Impede Command Injection
        subprocess.run(["git", "clone", "--depth", "1", clone_url, target], 
                       capture_output=True, timeout=60, check=True)
        
        all_findings = []
        
        # 1. Varredura SAST (Semgrep)
        try:
            semgrep_res = subprocess.run(["semgrep", "scan", "--config", "auto", "--json", target], 
                                         capture_output=True, text=True, timeout=120)
            if semgrep_res.stdout:
                raw_semgrep = json.loads(semgrep_res.stdout)
                for res in raw_semgrep.get('results', []):
                    all_findings.append({
                        "title": f"SAST: {res['check_id'].split('.')[-1]}",
                        "severity": "HIGH",
                        "file": os.path.relpath(res['path'], target),
                        "line": res['start']['line'],
                        "exploit": res['extra']['message']
                    })
        except: pass

        # 2. Varredura de Segredos (Regex Blindado)
        patterns = [
            (r'xox[bap]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}', "Slack Token"),
            (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "SendGrid API Key"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
            (r'AIza[0-9A-Za-z-_]{35}', "Google API Key"),
            (r'(?i)password\s*[:=]\s*["\'][^"\']{8,}["\']', "Senha Exposta")
        ]
        
        for root, _, files in os.walk(target):
            for file in files:
                if file.endswith(('.py', '.js', '.env', '.json', '.yml', '.conf')):
                    f_path = os.path.join(root, file)
                    rel = os.path.relpath(f_path, target)
                    with open(f_path, 'r', errors='ignore') as f:
                        for i, line in enumerate(f, 1):
                            for pat, label in patterns:
                                if re.search(pat, line):
                                    all_findings.append({
                                        "title": f"SECRET: {label}", 
                                        "severity": "CRITICAL", 
                                        "file": rel, 
                                        "line": i, 
                                        "exploit": RISK_LEVELS["CRITICAL"]
                                    })

        # Cálculo do Security Score
        penalty = (len([f for f in all_findings if f['severity'] == 'CRITICAL']) * 15) + \
                  (len([f for f in all_findings if f['severity'] == 'HIGH']) * 8)
        final_score = max(5, 100 - penalty)
        
        return jsonify({"findings": all_findings, "score": final_score})
    except Exception as e:
        return jsonify({"error": "Erro na integridade do scan. Verifique as permissões."}), 500

@app.route('/fetch_file', methods=['POST'])
def fetch_file():
    file_rel_path = request.form.get('filepath')
    # Proteção Path Traversal: impede leitura fora do diretório clone
    target_path = safe_join(os.path.join(TEMP_DIR, "clone"), file_rel_path)
    
    if target_path and os.path.exists(target_path):
        with open(target_path, 'r', errors='ignore') as f:
            return jsonify({"content": f.readlines()})
    return jsonify({"error": "Acesso proibido."}), 403

if __name__ == '__main__':
    if not os.path.exists('templates'): os.makedirs('templates')
    with open('templates/index.html', 'w') as f:
        f.write('''<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8"><title>SHIELD MASTER | CYBER DASHBOARD</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=JetBrains+Mono&display=swap" rel="stylesheet">
<style>
    body { background: radial-gradient(circle at center, #0a111f 0%, #020408 100%); color: #f8fafc; font-family: 'Inter', sans-serif; overflow: hidden; }
    .cyber-card { background: rgba(255, 255, 255, 0.02); backdrop-filter: blur(15px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; }
    .orbitron { font-family: 'Orbitron', sans-serif; }
    .line-highlight { background: rgba(239, 68, 68, 0.25) !important; border-left: 4px solid #ef4444; }
    .score-circle { transition: stroke-dashoffset 1s ease-in-out; transform: rotate(-90deg); transform-origin: 50% 50%; }
</style></head>
<body class="h-screen flex flex-col p-4 gap-4">
    <header class="cyber-card p-4 flex justify-between items-center shadow-2xl">
        <div class="flex items-center gap-4">
            <div class="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center shadow-[0_0_15px_rgba(37,99,235,0.4)] text-white orbitron font-black text-xl">S</div>
            <h1 class="orbitron font-black text-xl tracking-[4px] text-white">SHIELD<span class="text-blue-500">MASTER</span></h1>
        </div>
        <div class="flex gap-3 bg-black/40 p-2 rounded-xl border border-white/5">
            <input type="password" id="token" class="bg-transparent border-none text-[10px] w-32 focus:ring-0 text-blue-400" placeholder="🗝️ GITHUB TOKEN">
            <input type="text" id="url" class="bg-transparent border-none text-[10px] w-64 focus:ring-0 text-white" placeholder="🌐 REPOSITÓRIO URL">
            <button onclick="runAudit()" id="btn" class="bg-blue-600 hover:bg-blue-500 px-6 py-2 rounded-lg text-[10px] font-black orbitron transition-all">START SCAN</button>
        </div>
    </header>

    <main class="flex-1 grid grid-cols-12 gap-4 overflow-hidden">
        <div class="col-span-3 flex flex-col gap-4 overflow-hidden">
            <div class="cyber-card p-6 flex flex-col items-center justify-center text-center">
                <h3 class="orbitron text-[10px] text-slate-500 mb-4 tracking-widest uppercase">Security Score</h3>
                <div class="relative flex items-center justify-center">
                    <svg class="w-32 h-32">
                        <circle cx="64" cy="64" r="58" stroke="rgba(255,255,255,0.05)" stroke-width="8" fill="transparent"/>
                        <circle id="score-ring" cx="64" cy="64" r="58" stroke="#2563eb" stroke-width="8" fill="transparent" stroke-dasharray="364.4" stroke-dashoffset="364.4" class="score-circle" stroke-linecap="round"/>
                    </svg>
                    <span id="score-text" class="absolute orbitron text-3xl font-black text-white">0%</span>
                </div>
                <div id="status-badge" class="mt-4 px-4 py-1 rounded-full text-[9px] font-black border border-white/10 uppercase tracking-widest bg-white/5">STANDBY</div>
            </div>
            <div class="cyber-card flex-1 p-4 overflow-y-auto">
                <h3 class="orbitron text-[9px] text-slate-500 mb-4 tracking-widest uppercase">🚨 Incidents</h3>
                <div id="findings-list" class="space-y-3"></div>
            </div>
        </div>
        <div class="col-span-9 cyber-card flex flex-col overflow-hidden">
            <div id="file-path" class="p-3 bg-white/5 border-b border-white/5 text-[10px] text-blue-400 font-mono italic">> Ready for analysis...</div>
            <div id="code-container" class="flex-1 overflow-y-auto p-6 font-mono text-[12px] scroll-smooth">
                <div class="h-full flex items-center justify-center opacity-10">
                    <p class="orbitron text-sm">Waiting for repository input...</p>
                </div>
            </div>
        </div>
    </main>
    <script>
        function updateScore(score) {
            const ring = document.getElementById('score-ring');
            const text = document.getElementById('score-text');
            const badge = document.getElementById('status-badge');
            const offset = 364.4 - (364.4 * score / 100);
            ring.style.strokeDashoffset = offset;
            text.innerText = score + "%";
            if(score >= 80) { ring.style.stroke = "#10b981"; badge.innerText = "🛡️ SECURE"; badge.style.color = "#10b981"; }
            else if(score >= 50) { ring.style.stroke = "#f59e0b"; badge.innerText = "⚠️ WARNING"; badge.style.color = "#f59e0b"; }
            else { ring.style.stroke = "#ef4444"; badge.innerText = "💀 DANGER"; badge.style.color = "#ef4444"; }
        }
        async function runAudit() {
            const btn = document.getElementById('btn');
            btn.innerText = "RUNNING..."; btn.disabled = true;
            try {
                const res = await fetch('/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: `repo_url=${encodeURIComponent(document.getElementById('url').value)}&github_token=${encodeURIComponent(document.getElementById('token').value)}`
                });
                const data = await res.json();
                if(data.error) { alert(data.error); }
                else {
                    updateScore(data.score);
                    document.getElementById('findings-list').innerHTML = data.findings.map(f => `
                        <div onclick="loadFile('${f.file}', ${f.line})" class="p-3 border border-white/5 bg-white/5 rounded-xl cursor-pointer hover:bg-white/10 hover:border-blue-500/30 transition-all group">
                            <div class="flex justify-between items-start mb-1">
                                <span class="text-[9px] font-black text-red-500 uppercase">${f.title}</span>
                            </div>
                            <div class="text-[8px] text-slate-400 group-hover:text-blue-300 transition-colors truncate">${f.file} : L${f.line}</div>
                        </div>`).join('') || '<p class="text-green-500 orbitron text-[10px] p-4 text-center">✅ No Threats Found.</p>';
                }
            } catch(e) { alert("Scan failure."); }
            btn.innerText = "START SCAN"; btn.disabled = false;
        }
        async function loadFile(path, line) {
            document.getElementById('file-path').innerText = `> Viewing: ${path}`;
            const res = await fetch('/fetch_file', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: `filepath=${encodeURIComponent(path)}`
            });
            const data = await res.json();
            if(data.content) {
                document.getElementById('code-container').innerHTML = data.content.map((l, i) => {
                    const n = i + 1;
                    return `<div id="L${n}" class="flex gap-6 px-2 ${n === line ? 'line-highlight' : ''}">
                        <span class="w-8 text-right opacity-20 select-none text-blue-500 font-bold">${n}</span>
                        <span class="whitespace-pre text-slate-300">${l.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</span>
                    </div>`
                }).join('');
                setTimeout(() => { document.getElementById(`L${line}`)?.scrollIntoView({behavior:'smooth', block:'center'}); }, 100);
            }
        }
    </script>
</body></html>''')
    install_tools()
    app.run(host='0.0.0.0', port=7070)
