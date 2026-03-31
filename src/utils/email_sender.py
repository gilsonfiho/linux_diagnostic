"""
Email Sender - Envio do relatório PDF por Gmail SMTP
=====================================================
Configuração via .env:
    GMAIL_USER=seu.email@gmail.com
    GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
    EMAIL_DEST=destino@gmail.com
"""

import logging
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

logger = logging.getLogger(__name__)

GMAIL_SMTP_HOST = "smtp.gmail.com"
GMAIL_SMTP_PORT = 587


def _load_env_config() -> dict:
    """
    Carrega configurações de e-mail do ambiente (via .env ou variáveis de sistema).
    Tenta usar python-dotenv se disponível, senão usa os.environ.
    """
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        logger.debug("python-dotenv não instalado; usando apenas variáveis de ambiente do sistema")

    import os
    config = {
        "gmail_user": os.getenv("GMAIL_USER", "").strip(),
        "gmail_password": os.getenv("GMAIL_APP_PASSWORD", "").strip(),
        "email_dest": os.getenv("EMAIL_DEST", "").strip(),
    }
    return config


def send_pdf_report(pdf_path: Path, host: str) -> bool:
    """
    Envia o relatório PDF por e-mail via Gmail SMTP com TLS.

    Args:
        pdf_path: Caminho para o arquivo PDF gerado.
        host: Hostname/IP do servidor diagnosticado (usado no assunto).

    Returns:
        True se enviado com sucesso, False caso contrário.
    """
    config = _load_env_config()

    gmail_user = config["gmail_user"]
    gmail_password = config["gmail_password"]
    email_dest = config["email_dest"]

    missing = [k for k, v in {
        "GMAIL_USER": gmail_user,
        "GMAIL_APP_PASSWORD": gmail_password,
        "EMAIL_DEST": email_dest,
    }.items() if not v]

    if missing:
        logger.error(
            f"Variáveis de ambiente ausentes para envio de e-mail: {', '.join(missing)}. "
            "Configure o arquivo .env na raiz do projeto."
        )
        return False

    if not pdf_path.exists():
        logger.error(f"Arquivo PDF não encontrado para envio: {pdf_path}")
        return False

    subject = f"Relatório de Diagnóstico Linux - {host}"
    body = (
        f"Diagnóstico automatizado do servidor <b>{host}</b> concluído.<br><br>"
        f"O relatório completo em PDF está em anexo.<br><br>"
        f"<i>Gerado por Linux SSH Diagnostics</i>"
    )

    msg = MIMEMultipart()
    msg["From"] = gmail_user
    msg["To"] = email_dest
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))

    with open(pdf_path, "rb") as f:
        attachment = MIMEApplication(f.read(), _subtype="pdf")
        attachment.add_header(
            "Content-Disposition", "attachment", filename=pdf_path.name
        )
        msg.attach(attachment)

    try:
        logger.info(f"Conectando ao Gmail SMTP ({GMAIL_SMTP_HOST}:{GMAIL_SMTP_PORT})...")
        with smtplib.SMTP(GMAIL_SMTP_HOST, GMAIL_SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(gmail_user, gmail_password)
            server.sendmail(gmail_user, email_dest, msg.as_string())

        logger.info(f"E-mail enviado com sucesso para {email_dest}")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error(
            "Falha de autenticação Gmail. Verifique GMAIL_USER e GMAIL_APP_PASSWORD no .env. "
            "Certifique-se de usar uma App Password (não a senha pessoal)."
        )
    except smtplib.SMTPException as e:
        logger.error(f"Erro SMTP ao enviar e-mail: {e}")
    except OSError as e:
        logger.error(f"Erro de rede ao conectar ao Gmail SMTP: {e}")

    return False
