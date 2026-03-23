"""
Logger Utility
===============
Configuração centralizada de logging para o sistema de diagnóstico.
Suporta saída para console (colorida) e arquivo.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """
    Formatter com cores ANSI para melhor legibilidade no terminal.
    Usa cores diferentes por nível de log.
    """

    # Códigos ANSI de cor
    COLORS = {
        "DEBUG":    "\033[36m",   # Ciano
        "INFO":     "\033[32m",   # Verde
        "WARNING":  "\033[33m",   # Amarelo
        "ERROR":    "\033[31m",   # Vermelho
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{self.BOLD}{record.levelname:8}{self.RESET}"
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
) -> None:
    """
    Configura o sistema de logging da aplicação.

    Args:
        level: Nível de log ("DEBUG", "INFO", "WARNING", "ERROR").
        log_file: Caminho opcional para arquivo de log.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Remove handlers existentes (evita duplicação em reconfiguração)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(numeric_level)

    # Handler de console com formatação colorida
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_format = ColoredFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)

    # Handler de arquivo (sem cores, formato completo)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # Arquivo sempre em DEBUG
        file_format = logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_format)
        root_logger.addHandler(file_handler)

    # Silencia loggers verbosos de bibliotecas externas
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("paramiko.transport").setLevel(logging.ERROR)
