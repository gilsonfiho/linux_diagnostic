#!/usr/bin/env python3
"""
Linux SSH Diagnostics - Main Entry Point
=========================================
Sistema de diagnóstico automatizado de sistemas Linux via SSH.

Uso:
    python main.py --host <IP> --user <usuário> [opções]

Exemplos:
    python main.py --host 192.168.1.100 --user pi --password mypass
    python main.py --host 192.168.1.100 --user pi --key ~/.ssh/id_rsa
    python main.py --host 192.168.1.100 --user pi --key ~/.ssh/id_rsa --output ./reports
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

from src.collector.ssh_client import SSHClient
from src.collector.system_collector import SystemCollector
from src.analyzer.diagnostic_analyzer import DiagnosticAnalyzer
from src.reporter.report_generator import ReportGenerator
from src.utils.logger import setup_logging


def parse_arguments() -> argparse.Namespace:
    """
    Configura e processa os argumentos de linha de comando.

    Returns:
        argparse.Namespace: Argumentos processados.
    """
    parser = argparse.ArgumentParser(
        description="Diagnóstico automatizado de sistemas Linux via SSH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Conexão SSH
    conn_group = parser.add_argument_group("Conexão SSH")
    conn_group.add_argument("--host", required=True, help="IP ou hostname do servidor")
    conn_group.add_argument("--port", type=int, default=22, help="Porta SSH (padrão: 22)")
    conn_group.add_argument("--user", required=True, help="Usuário SSH")

    # Autenticação (mutuamente exclusivos)
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--password", help="Senha do usuário")
    auth_group.add_argument("--key", help="Caminho para chave SSH privada")

    # Opções de saída
    out_group = parser.add_argument_group("Saída")
    out_group.add_argument(
        "--output",
        default="./reports",
        help="Diretório para salvar relatórios (padrão: ./reports)",
    )
    out_group.add_argument(
        "--format",
        choices=["markdown", "pdf", "both"],
        default="both",
        help="Formato do relatório (padrão: both)",
    )

    # Diagnóstico
    diag_group = parser.add_argument_group("Diagnóstico")
    diag_group.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout para comandos SSH em segundos (padrão: 30)",
    )
    diag_group.add_argument(
        "--raspberry",
        action="store_true",
        help="Ativar coleta específica para Raspberry Pi",
    )

    # Logging
    log_group = parser.add_argument_group("Logging")
    log_group.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Nível de log (padrão: INFO)",
    )
    log_group.add_argument("--log-file", help="Arquivo de log (opcional)")

    return parser.parse_args()


def main() -> int:
    """
    Função principal do sistema de diagnóstico.

    Returns:
        int: Código de saída (0 = sucesso, 1 = erro).
    """
    args = parse_arguments()

    # Configurar logging
    setup_logging(level=args.log_level, log_file=args.log_file)
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("Linux SSH Diagnostics iniciado")
    logger.info(f"Alvo: {args.user}@{args.host}:{args.port}")
    logger.info("=" * 60)

    # Preparar diretório de saída
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Estabelecer conexão SSH
        logger.info("Etapa 1/4: Conectando ao servidor SSH...")
        ssh_client = SSHClient(
            host=args.host,
            port=args.port,
            username=args.user,
            password=args.password,
            key_path=args.key,
            timeout=args.timeout,
        )

        with ssh_client as client:
            logger.info(f"Conexão estabelecida com {args.host}")

            # 2. Coletar dados do sistema
            logger.info("Etapa 2/4: Coletando dados do sistema...")
            collector = SystemCollector(
                ssh_client=client,
                is_raspberry_pi=args.raspberry,
                timeout=args.timeout,
            )
            system_data = collector.collect_all()
            logger.info(
                f"Coleta concluída: {len(system_data)} conjuntos de dados obtidos"
            )

            # 3. Analisar dados
            logger.info("Etapa 3/4: Analisando dados coletados...")
            analyzer = DiagnosticAnalyzer()
            diagnostic_result = analyzer.analyze(system_data)
            logger.info(
                f"Análise concluída: {len(diagnostic_result.issues)} problemas identificados"
            )

            # 4. Gerar relatório
            logger.info("Etapa 4/4: Gerando relatório...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_name = f"diagnostic_{args.host}_{timestamp}"

            generator = ReportGenerator(
                output_dir=output_dir,
                report_name=report_name,
            )

            generated_files = generator.generate(
                diagnostic_result=diagnostic_result,
                system_data=system_data,
                connection_info={
                    "host": args.host,
                    "port": args.port,
                    "user": args.user,
                },
                output_format=args.format,
            )

            logger.info("=" * 60)
            logger.info("Diagnóstico concluído com sucesso!")
            logger.info("Arquivos gerados:")
            for f in generated_files:
                logger.info(f"  - {f}")

            # Resumo rápido
            from src.analyzer.diagnostic_analyzer import Severity

            critical = sum(
                1 for i in diagnostic_result.issues if i.severity == Severity.CRITICAL
            )
            warnings = sum(
                1 for i in diagnostic_result.issues if i.severity == Severity.WARNING
            )
            info = sum(
                1 for i in diagnostic_result.issues if i.severity == Severity.INFO
            )

            logger.info(
                f"Resumo: {critical} crítico(s), {warnings} aviso(s), {info} info(s)"
            )
            logger.info("=" * 60)

        return 0

    except ConnectionError as e:
        logger.error(f"Falha na conexão SSH: {e}")
        return 1
    except TimeoutError as e:
        logger.error(f"Timeout na operação: {e}")
        return 1
    except KeyboardInterrupt:
        logger.info("Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        logger.exception(f"Erro inesperado: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
