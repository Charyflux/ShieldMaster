# 🛡️ ShieldMaster | Cyber Security Auditor

O **ShieldMaster** é uma ferramenta de auditoria de segurança automatizada projetada para realizar varreduras rápidas em repositórios do GitHub. Ele combina análise estática de código (SAST) com detecção de segredos expostos, entregando um diagnóstico visual em um dashboard moderno.



---

## 🚀 Funcionalidades

* **Clonagem Segura:** Integração com GitHub via URL e Token com sanitização de comandos.
* **SAST (Static Analysis Security Testing):** Identifica vulnerabilidades lógicas e padrões de código inseguros usando o motor **Semgrep**.
* **Secret Scanning:** Localiza chaves de API (AWS, Google, Slack, etc.) e senhas "hardcoded" através de Regex de alta precisão.
* **Visualizador de Código:** Interface interativa para inspecionar a linha exata onde a vulnerabilidade foi detectada.
* **Security Score:** Algoritmo que calcula o nível de risco do projeto (0-100%).

---

## 🛠️ Stack Tecnológica

| Componente | Tecnologia |
| :--- | :--- |
| **Backend** | Python / Flask |
| **Motores de Scan** | Semgrep & TruffleHog |
| **Frontend** | HTML5 / Tailwind CSS |
| **UI/UX** | Design inspirado em Cyberpunk / Orbitron Fonts |
| **Segurança** | Shlex & Safe Join (Proteção contra Injection e Traversal) |

---

## 📦 Como Instalar e Rodar

### Pré-requisitos
* Python 3.x instalado.
* Git instalado.

### Passo a Passo
1. Clone este repositório:
   ```bash
   git clone [https://github.com/Charyflux/ShieldMaster.git](https://github.com/Charyflux/ShieldMaster.git)
   cd ShieldMaster
