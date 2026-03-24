# 🖥️ Linux SSH Diagnostics

Sistema de **diagnóstico automatizado de sistemas Linux via SSH**.  
Conecta remotamente, coleta dados críticos, analisa e gera relatórios em Markdown e PDF.

---

## ✨ Funcionalidades

- 🔐 **Conexão SSH** por senha ou chave privada
- 📊 **Coleta automática** de: CPU, memória, disco, temperatura, USB, logs, serviços
- 🔍 **Análise inteligente** com classificação em `CRITICAL`, `WARNING`, `INFO`
- 📄 **Relatório em Markdown** detalhado e estruturado
- 📑 **Relatório em PDF** gerado automaticamente
- 🍓 **Suporte a Raspberry Pi** (vcgencmd, thermal_zones)

---

## 📁 Estrutura do Projeto

```
linux-ssh-diagnostics/
├── main.py                          # Entry point principal
├── requirements.txt                 # Dependências Python
├── setup.py                         # Instalação como pacote
├── README.md                        # Este arquivo
├── .gitignore
├── src/
│   ├── collector/
│   │   ├── ssh_client.py            # Conexão SSH (paramiko)
│   │   └── system_collector.py      # Coleta de dados do sistema
│   ├── analyzer/
│   │   └── diagnostic_analyzer.py   # Análise e classificação de problemas
│   ├── reporter/
│   │   ├── report_generator.py      # Geração de relatórios
│   │   └── pdf_renderer.py          # Renderização PDF (fpdf2)
│   └── utils/
│       └── logger.py                # Configuração de logging
├── tests/
│   ├── conftest.py                  # Configuração global do pytest
│   ├── mock_ssh_client.py           # Mock SSH (testes sem servidor real)
│   ├── test_system_collector.py     # Testes do coletor de dados
│   ├── test_diagnostic_analyzer.py  # Testes do analisador (regras + severidades)
│   └── test_report_generator.py     # Testes de geração de relatórios + E2E
└── reports/                         # Relatórios gerados (criado automaticamente)
```

---

## 🚀 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/linux-ssh-diagnostics.git
cd linux-ssh-diagnostics
```

### 2. Crie um ambiente virtual (recomendado)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
```

### 3. Instale as dependências

```bash
pip install -r requirements.txt
```

---

## 🎯 Uso

### Autenticação por senha

```bash
python main.py --host 192.168.1.100 --user pi --password minhasenha
```

### Autenticação por chave SSH

```bash
python main.py --host 192.168.1.100 --user pi --key ~/.ssh/id_rsa
```

### Raspberry Pi (ativa coleta específica)

```bash
python main.py --host 192.168.1.50 --user pi --key ~/.ssh/id_rsa --raspberry
```

### Gerar apenas Markdown

```bash
python main.py --host 192.168.1.100 --user admin --password pass --format markdown
```

### Com log detalhado salvo em arquivo

```bash
python main.py --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa \
  --log-level DEBUG --log-file ./logs/diag.log
```

### Relatório em diretório customizado

```bash
python main.py --host 192.168.1.100 --user pi --password pass \
  --output /tmp/meus-relatorios
```

---

## ⚙️ Opções Completas

```
usage: main.py [-h] --host HOST [--port PORT] --user USER
               (--password PASSWORD | --key KEY)
               [--output OUTPUT] [--format {markdown,pdf,both}]
               [--timeout TIMEOUT] [--raspberry]
               [--log-level {DEBUG,INFO,WARNING,ERROR}] [--log-file LOG_FILE]

Conexão SSH:
  --host HOST           IP ou hostname do servidor
  --port PORT           Porta SSH (padrão: 22)
  --user USER           Usuário SSH

Autenticação (obrigatório um):
  --password PASSWORD   Senha do usuário
  --key KEY             Caminho para chave SSH privada

Saída:
  --output OUTPUT       Diretório para relatórios (padrão: ./reports)
  --format              markdown | pdf | both (padrão: both)

Diagnóstico:
  --timeout TIMEOUT     Timeout SSH em segundos (padrão: 30)
  --raspberry           Ativar coleta para Raspberry Pi

Logging:
  --log-level           DEBUG | INFO | WARNING | ERROR (padrão: INFO)
  --log-file            Arquivo de log opcional
```

---

## 📊 O que é coletado e analisado

| Categoria        | Comandos                              | Análise                              |
|------------------|---------------------------------------|--------------------------------------|
| **Sistema**      | `uname`, `os-release`, `hostname`     | Identificação do sistema             |
| **Performance**  | `top -bn1`, `uptime`, `/proc/loadavg` | Carga crítica de CPU                 |
| **Memória**      | `free -m`                             | Uso alto de RAM e swap               |
| **Disco**        | `df -h`, `lsblk`                      | Disco cheio (>80% warning, >90% crit)|
| **Temperatura**  | `sensors`, `thermal_zones`, `vcgencmd`| Superaquecimento (>70°C warn, >85°C crit)|
| **USB**          | `lsusb`, `dmesg` grep USB             | Desconexões, sobrecorrente           |
| **Logs**         | `dmesg -T`, `journalctl -p3 -xb`      | Kernel panic, OOM kill, I/O errors   |
| **Serviços**     | `systemctl --failed`                  | Serviços com falha                   |
| **Rede**         | `ip addr`, `ss -tlnp`                 | Interfaces e portas abertas          |

---

## 📄 Estrutura do Relatório

1. **Cabeçalho** — Informações de conexão, sistema e saúde geral
2. **Resumo Executivo** — Visão geral dos problemas e contagem por severidade
3. **Problemas Críticos 🔴** — Com descrição, recomendação e evidência
4. **Avisos 🟡** — Itens que requerem atenção
5. **Informações 🟢** — Status normal do sistema
6. **Dados Técnicos Brutos** — Saída completa dos comandos coletados

---

## 🧪 Testes

Os testes usam um **MockSSHClient** que simula respostas Linux reais, permitindo execução completa sem nenhum servidor SSH disponível.

```bash
# Rodar todos os testes
pytest

# Com cobertura de código
pytest --cov=src --cov-report=term-missing

# Testes específicos
pytest tests/test_system_collector.py -v
pytest tests/test_diagnostic_analyzer.py -v
pytest tests/test_report_generator.py -v

# Apenas testes E2E (fluxo completo)
pytest tests/test_report_generator.py::TestEndToEnd -v
```

### Cenários de mock disponíveis

| Cenário | Descrição |
|---------|-----------|
| `"normal"` | Sistema saudável — disco 37%, CPU baixa, temperatura 42°C |
| `"critical"` | Disco 97%, RAM 98%, CPU sobrecarregada, temperatura 88°C, kernel panic no dmesg |
| `"warnings"` | Disco 85/82%, swap em uso, serviços nginx/postgresql com falha, múltiplas desconexões USB |

```python
# Uso direto do mock em scripts (a partir da raiz do projeto)
import sys
sys.path.insert(0, "tests")

from mock_ssh_client import MockSSHClient
from src.collector.system_collector import SystemCollector

mock = MockSSHClient("critical")
collector = SystemCollector(ssh_client=mock)
data = collector.collect_all()
```

---

## 🔧 Requisitos

- Python **3.9+**
- Acesso SSH ao servidor alvo
- `paramiko` (conexão SSH)
- `fpdf2` (geração de PDF — opcional, Markdown sempre funciona)

---

## 🏗️ Arquitetura

```
main.py
  └─► SSHClient          # Conexão e execução de comandos
        └─► SystemCollector   # Executa 20+ comandos diagnósticos
              └─► DiagnosticAnalyzer  # Analisa e classifica problemas
                    └─► ReportGenerator  # Gera Markdown + PDF
```

---

## 📝 Licença

MIT License — use livremente.
