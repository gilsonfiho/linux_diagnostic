"""
SSH Client
===========
Módulo responsável pela conexão SSH com servidores remotos.
Suporta autenticação por senha e por chave SSH.
"""

import logging
import socket
from pathlib import Path
from typing import Optional, Tuple

import paramiko

logger = logging.getLogger(__name__)


class SSHConnectionError(Exception):
    """Exceção customizada para erros de conexão SSH."""
    pass


class SSHClient:
    """
    Cliente SSH para conexão com servidores Linux remotos.

    Suporta:
    - Autenticação por usuário/senha
    - Autenticação por chave SSH privada
    - Context manager (with statement)
    - Timeout configurável
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Inicializa o cliente SSH.

        Args:
            host: Endereço IP ou hostname do servidor.
            port: Porta SSH (padrão: 22).
            username: Nome do usuário.
            password: Senha do usuário (opcional).
            key_path: Caminho para chave SSH privada (opcional).
            timeout: Timeout de conexão e execução em segundos.

        Raises:
            ValueError: Se nem senha nem chave forem fornecidos.
        """
        if not password and not key_path:
            raise ValueError("Forneça --password ou --key para autenticação.")

        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self) -> None:
        """
        Estabelece a conexão SSH com o servidor remoto.

        Raises:
            SSHConnectionError: Em caso de falha na conexão.
        """
        logger.debug(f"Iniciando conexão SSH para {self.username}@{self.host}:{self.port}")

        self._client = paramiko.SSHClient()
        # Aceita automaticamente novas chaves de host (adequado para diagnóstico)
        # Em produção, considere usar RejectPolicy ou WarningPolicy
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "banner_timeout": self.timeout,
            "auth_timeout": self.timeout,
        }

        try:
            if self.key_path:
                # Autenticação por chave SSH
                key_file = Path(self.key_path).expanduser()
                if not key_file.exists():
                    raise SSHConnectionError(f"Chave SSH não encontrada: {self.key_path}")

                logger.debug(f"Usando autenticação por chave: {self.key_path}")
                connect_kwargs["key_filename"] = str(key_file)
            else:
                # Autenticação por senha
                logger.debug("Usando autenticação por senha")
                connect_kwargs["password"] = self.password

            self._client.connect(**connect_kwargs)
            logger.info(f"Conexão SSH estabelecida: {self.username}@{self.host}:{self.port}")

        except paramiko.AuthenticationException as e:
            raise SSHConnectionError(f"Falha de autenticação para {self.username}@{self.host}: {e}")
        except paramiko.SSHException as e:
            raise SSHConnectionError(f"Erro SSH ao conectar em {self.host}: {e}")
        except socket.timeout:
            raise SSHConnectionError(
                f"Timeout ao conectar em {self.host}:{self.port} (>{self.timeout}s)"
            )
        except socket.error as e:
            raise SSHConnectionError(f"Erro de rede ao conectar em {self.host}: {e}")

    def disconnect(self) -> None:
        """Encerra a conexão SSH de forma segura."""
        if self._client:
            self._client.close()
            self._client = None
            logger.debug(f"Conexão SSH encerrada: {self.host}")

    def execute_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        ignore_errors: bool = False,
    ) -> Tuple[str, str, int]:
        """
        Executa um comando no servidor remoto via SSH.

        Args:
            command: Comando shell a ser executado.
            timeout: Timeout específico para este comando (usa o padrão se None).
            ignore_errors: Se True, não levanta exceção em caso de erro.

        Returns:
            Tuple[str, str, int]: (stdout, stderr, exit_code)

        Raises:
            SSHConnectionError: Se não houver conexão ativa.
            RuntimeError: Se o comando falhar e ignore_errors=False.
        """
        if not self._client:
            raise SSHConnectionError("Sem conexão SSH ativa. Chame connect() primeiro.")

        effective_timeout = timeout or self.timeout
        logger.debug(f"Executando: {command}")

        try:
            stdin, stdout, stderr = self._client.exec_command(
                command, timeout=effective_timeout
            )

            # Lê saídas
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0 and not ignore_errors:
                logger.debug(f"Comando retornou código {exit_code}: {command}")
                if err:
                    logger.debug(f"Stderr: {err[:200]}")

            return out, err, exit_code

        except socket.timeout:
            logger.warning(f"Timeout ao executar comando: {command}")
            return "", f"Timeout após {effective_timeout}s", -1
        except paramiko.SSHException as e:
            logger.error(f"Erro SSH ao executar '{command}': {e}")
            if not ignore_errors:
                raise
            return "", str(e), -1

    def is_connected(self) -> bool:
        """
        Verifica se a conexão SSH está ativa.

        Returns:
            bool: True se conectado, False caso contrário.
        """
        if not self._client:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    # Context manager para uso com 'with'
    def __enter__(self) -> "SSHClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
