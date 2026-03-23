"""
conftest.py - Configuração global do pytest.

Garante que o diretório raiz do projeto e o diretório de testes
estejam no sys.path, permitindo imports sem necessidade de __init__.py.
"""

import sys
from pathlib import Path

# Raiz do projeto → habilita: from src.*
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Diretório tests/ → habilita: from mock_ssh_client import MockSSHClient
TESTS_DIR = Path(__file__).parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
