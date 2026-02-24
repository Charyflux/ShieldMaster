from flask import Flask, render_template, request, jsonify
import subprocess, os, shutil, re, json, time
from datetime import datetime

app = Flask(__name__)
TEMP_DIR = os.path.join(os.getcwd(), ".audit_internal_v25")

# Mapeamento de Exploração Hacker
EXPLOIT_MAP = {
    "TOKEN DETECTADO": "🔓 CRÍTICO: Atacante pode assumir instantaneamente infraestrutura cloud (AWS/Azure/GCP), exfiltrar repositórios privados e estabelecer backdoor persistente.",
    "AVOID_APP_RUN_WITH_BAD_HOST": "🌐 AVISO: Servidor exposto em 0.0.0.0 permite que atacantes remotos contornem firewalls e acedam a endpoints de desenvolvimento diretamente.",
    "CREDENCIAL EXPOSTA": "💀 CRÍTICO: Credenciais expostas permitem movimento lateral, escalamento de privilégios e comprometimento total da base de dados em minutos.",
    "HARDCODED SECRET": "🔑 ALTO: Chaves de API expostas levam a acesso não autorizado a dados, abuso de mineração crypto e comprometimento de contas de serviço.",
    "SQL_INJECTION": "⚡ CRÍTICO: Atacantes podem extrair base de dados completa, contornar autenticação e executar comandos remotos via SQLi.",
    "XSS_VULN": "🎯 MÉDIO: Cross-site scripting permite sequestro de sessão, roubo de credenciais e distribuição de malware para utilizadores.",
    "INSECURE_DESERIALIZATION": "💣 CRÍTICO: Execução remota de código possível através de desserialização insegura - comprometimento total do servidor.",
    "DEFAULT": "⚠️ Esta vulnerabilidade serve como ponto de entrada para escalamento de privilégios e ataques de negação de serviço."
}

def run_cmd(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)

@app.route('/')
def index(): 
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def run_scan():
    start_time = time.time()
    url, token = request.form.get('repo_url', '').strip(), request.form.get('github_token', '').strip()
    target = os.path.join(TEMP_DIR, "clone")
    
    try:
        if os.path.exists(TEMP_DIR): shutil.rmtree(TEMP_DIR)
        os.makedirs(target)
        
        repo_path = re.search(r'github\.com/(.+)', url.replace(".git", "")).group(1)
        run_cmd(["git", "clone", "--depth", "1", f"https://{token}@github.com/{repo_path}.git", target])
        
        findings = []
        scan_metadata = {
            "repo": repo_path,
            "timestamp": datetime.now().isoformat(),
            "duration": 0,
            "files_scanned": 0,
            "lines_analyzed": 0
        }

        # 1. BUSCA AVANÇADA POR CREDENCIAIS
        credential_patterns = [
            (r'(?i)(password|passwd|senha|pwd|secret|db_pass|admin_key|api[_-]?key|auth_token|access[_-]?token|client_secret|private[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']', "CREDENCIAL EXPOSTA"),
            (r'(?i)(mongodb|postgres|mysql|redis|elasticsearch)://[^:]+:[^@]+@', "URI BASE DE DADOS EXPOSTA"),
            (r'(?i)-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', "CHAVE PRIVADA EXPOSTA"),
            (r'(?i)aws[_\-]?(key|secret)_?(id|key)?\s*=\s*["\'][A-Z0-9]{16,}["\']', "CHAVE AWS DETECTADA"),
        ]

        for root, _, files in os.walk(target):
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.env', '.json', '.yml', '.yaml', '.xml', '.config', '.ini', '.conf', '.git/config')):
                    scan_metadata['files_scanned'] += 1
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                            lines = f.readlines()
                            scan_metadata['lines_analyzed'] += len(lines)
                            for i, line in enumerate(lines, 1):
                                for pattern, title in credential_patterns:
                                    if re.search(pattern, line) and len(line.strip()) < 200:
                                        findings.append({
                                            "id": f"cred-{len(findings)}",
                                            "title": f"🔐 {title}",
                                            "severity": "CRÍTICO",
                                            "color": "#FF3B3B",
                                            "badge": "🔥 CRÍTICO",
                                            "desc": "Credenciais hardcoded detetadas no código fonte",
                                            "exploit": EXPLOIT_MAP.get(title, EXPLOIT_MAP["DEFAULT"]),
                                            "evidence": f"📁 {file}:{i} → {line.strip()[:100]}",
                                            "line": i,
                                            "file": file,
                                            "filepath": filepath,
                                            "code_snippet": line.strip(),
                                            "remediation": "Use variáveis de ambiente ou gestores de segredos (Vault, AWS Secrets Manager)"
                                        })
                    except: continue

        # 2. TRUFFLEHOG (Secrets de alta precisão)
        th_res = run_cmd(["trufflehog", "filesystem", "--json", "--no-update", target])
        for line in th_res.stdout.splitlines():
            try:
                s = json.loads(line)
                file_path = s.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'desconhecido')
                findings.append({
                    "id": f"th-{len(findings)}",
                    "title": "🔥 SEGREDO CRÍTICO DETETADO",
                    "severity": "CRÍTICO",
                    "color": "#FF0000",
                    "badge": "💀 CRÍTICO",
                    "desc": f"Tipo de segredo: {s.get('DecoderName', 'Desconhecido')}",
                    "exploit": EXPLOIT_MAP["TOKEN DETECTADO"],
                    "evidence": f"📁 {file_path}",
                    "line": 1,
                    "file": os.path.basename(file_path),
                    "filepath": file_path,
                    "remediation": "Revogue imediatamente e rode todas as credenciais"
                })
            except: continue

        # 3. SEMGREP (Análise avançada de código)
        s_res = run_cmd(["semgrep", "scan", "--config=p/security-audit", "--config=p/owasp-top-ten", "--json", target])
        if s_res.stdout:
            s_data = json.loads(s_res.stdout)
            for r in s_data.get('results', []):
                severity = r['extra']['severity'].upper()
                color = "#FF6B6B" if severity == "ERROR" else "#FFA500" if severity == "WARNING" else "#FFD700"
                badge = "🚨 CRÍTICO" if severity == "ERROR" else "⚠️ AVISO" if severity == "WARNING" else "📌 INFO"
                
                findings.append({
                    "id": f"semgrep-{len(findings)}",
                    "title": f"🛡️ {r['check_id'].split('.')[-1]}",
                    "severity": severity,
                    "color": color,
                    "badge": badge,
                    "desc": r['extra']['message'],
                    "exploit": EXPLOIT_MAP.get(r['check_id'].split('.')[-1], EXPLOIT_MAP["DEFAULT"]),
                    "evidence": f"📁 Linha {r['start']['line']}: {r['extra'].get('lines', 'N/A').strip()[:100]}",
                    "line": r['start']['line'],
                    "file": r['path'],
                    "filepath": os.path.join(target, r['path']),
                    "cwe": r['extra'].get('metadata', {}).get('cwe', 'N/A'),
                    "remediation": r['extra'].get('metadata', {}).get('fix', 'Revise e corrija esta vulnerabilidade')
                })

        # 4. BANDIT (Python security)
        bandit_res = run_cmd(["bandit", "-r", target, "-f", "json"])
        if bandit_res.stdout:
            bandit_data = json.loads(bandit_res.stdout)
            for issue in bandit_data.get('results', []):
                findings.append({
                    "id": f"bandit-{len(findings)}",
                    "title": f"🐍 {issue['test_name']}",
                    "severity": issue['issue_severity'],
                    "color": "#FF4444" if issue['issue_severity'] == 'HIGH' else "#FF8844",
                    "badge": "💥 ALTO" if issue['issue_severity'] == 'HIGH' else "⚠️ MÉDIO",
                    "desc": issue['issue_text'],
                    "exploit": "Atacantes podem explorar isto para RCE ou fuga de dados",
                    "evidence": f"📁 {issue['filename']}:{issue['line_number']}",
                    "line": issue['line_number'],
                    "file": issue['filename'],
                    "filepath": issue['filename'],
                    "remediation": issue['test_id']
                })

        # Calcular score e estatísticas
        severity_weights = {"CRÍTICO": 15, "ALTO": 10, "MÉDIO": 5, "BAIXO": 2}
        total_weight = sum(severity_weights.get(f['severity'], 5) for f in findings)
        scan_metadata['duration'] = round(time.time() - start_time, 2)
        
        base_score = max(0, 100 - min(total_weight, 95))
        
        return jsonify({
            "findings": findings,
            "score": base_score,
            "metadata": scan_metadata,
            "summary": {
                "critical": sum(1 for f in findings if f['severity'] == "CRÍTICO"),
                "high": sum(1 for f in findings if f['severity'] == "ALTO"),
                "medium": sum(1 for f in findings if f['severity'] == "MÉDIO"),
                "low": sum(1 for f in findings if f['severity'] == "BAIXO"),
                "total": len(findings)
            }
        })
        
    except Exception as e:
        return jsonify({"error": f"Scan falhou: {str(e)}"}), 500
    finally:
        if os.path.exists(TEMP_DIR): 
            try: shutil.rmtree(TEMP_DIR)
            except: pass

@app.route('/fix', methods=['POST'])
def fix_vulnerability():
    data = request.get_json()
    finding_id = data.get('finding_id')
    filepath = data.get('filepath')
    line = data.get('line')
    vuln_type = data.get('type')
    
    try:
        if not os.path.exists(filepath):
            return jsonify({"success": False, "message": "Ficheiro não encontrado"})
        
        # Backup do ficheiro original
        backup_path = filepath + '.backup'
        shutil.copy2(filepath, backup_path)
        
        # Ler o ficheiro
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # CORREÇÃO REAL DOS DADOS
        if line and line > 0 and line <= len(lines):
            original_line = lines[line-1]
            
            # Para credenciais hardcoded
            if 'CREDENCIAL' in vuln_type or 'SEGREDO' in vuln_type or 'TOKEN' in vuln_type:
                # Extrair o nome da variável
                var_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]', original_line)
                if var_match:
                    var_name = var_match.group(1).upper()
                    
                    # Comentar a linha original e adicionar versão segura
                    if '.py' in filepath:
                        lines[line-1] = f"# 🔒 CORRIGIDO: {original_line.strip()}\n{var_match.group(1)} = os.getenv('{var_name}', '')  # Seguro\n"
                    elif '.js' in filepath:
                        lines[line-1] = f"// 🔒 CORRIGIDO: {original_line.strip()}\n{var_match.group(1)} = process.env.{var_name} || '';  // Seguro\n"
                    else:
                        # Para .env, .config, etc - remover a linha
                        lines[line-1] = f"# {original_line.strip()}  # 🔒 REMOVIDO - Use variáveis de ambiente\n"
            
            # Para SQL Injection
            elif 'SQL' in vuln_type:
                # Comentar a linha perigosa e adicionar aviso
                lines[line-1] = f"# 🚨 SQL INJECTION RISK - {original_line.strip()}\n# Use parametrized queries instead\n"
            
            # Para XSS
            elif 'XSS' in vuln_type:
                lines[line-1] = f"# 🚨 XSS RISK - {original_line.strip()}\n# Use escape functions\n"
        
        # Escrever o ficheiro corrigido
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        # Commit da correção
        try:
            # Encontrar o diretório do repositório
            repo_dir = filepath
            while repo_dir and not os.path.exists(os.path.join(repo_dir, '.git')):
                repo_dir = os.path.dirname(repo_dir)
            
            if repo_dir and os.path.exists(os.path.join(repo_dir, '.git')):
                # Configurar git user se necessário
                run_cmd(["git", "-C", repo_dir, "config", "user.email", "bountyhunter@nexus.security"])
                run_cmd(["git", "-C", repo_dir, "config", "user.name", "Nexus Bug Bounty Hunter"])
                
                # Fazer commit
                run_cmd(["git", "-C", repo_dir, "add", filepath])
                run_cmd(["git", "-C", repo_dir, "commit", "-m", f"🔒 fix: Critical security vulnerability patched - {vuln_type}"])
                
                # Tentar push (pode falhar se não tiver permissão)
                push_result = run_cmd(["git", "-C", repo_dir, "push"])
                
                commit_success = push_result.returncode == 0
            else:
                commit_success = False
                
        except Exception as e:
            print(f"Git error: {e}")
            commit_success = False
        
        # Ler o ficheiro corrigido para mostrar no preview
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            fixed_content = f.read()
        
        return jsonify({
            "success": True,
            "message": f"🔥 VULNERABILIDADE CORRIGIDA COM SUCESSO!\n\n• Ficheiro: {os.path.basename(filepath)}\n• Linha {line} corrigida\n• Backup criado: {os.path.basename(backup_path)}" + ("\n• Commit realizado no git" if commit_success else "\n• Commit falhou (sem acesso git)"),
            "fixed_content": fixed_content,
            "bounty_hunter": "Bug Bounty Hunter - Recompensa registada",
            "commit_success": commit_success
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro na correção: {str(e)}"})

@app.route('/file_content', methods=['POST'])
def get_file_content():
    data = request.get_json()
    filepath = data.get('filepath')
    line = data.get('line')
    
    try:
        if not os.path.exists(filepath):
            return jsonify({"success": False, "message": "Ficheiro não encontrado"})
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Preparar código com contexto
        start_line = max(0, line - 10)
        end_line = min(len(lines), line + 10)
        
        code_context = []
        for i in range(start_line, end_line):
            line_num = i + 1
            prefix = "→" if line_num == line else " "
            code_context.append({
                "line": line_num,
                "content": lines[i].rstrip('\n'),
                "is_vulnerable": line_num == line
            })
        
        return jsonify({
            "success": True,
            "filepath": filepath,
            "code": code_context,
            "total_lines": len(lines)
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7070, debug=False)
