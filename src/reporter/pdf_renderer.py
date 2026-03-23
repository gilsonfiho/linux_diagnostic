"""
PDF Renderer
=============
Módulo para geração de PDF a partir de conteúdo Markdown.
Utiliza fpdf2 para renderização.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


def render_pdf_with_fpdf(markdown_content: str, output_path: Path) -> None:
    """
    Gera um PDF formatado a partir do conteúdo Markdown usando fpdf2.

    Args:
        markdown_content: Conteúdo do relatório em Markdown.
        output_path: Caminho do arquivo PDF de saída.

    Raises:
        ImportError: Se fpdf2 não estiver instalado.
        Exception: Em caso de falha na geração.
    """
    from fpdf import FPDF  # type: ignore  # levanta ImportError se fpdf2 ausente
    from fpdf.enums import XPos, YPos  # type: ignore  # introduzido no fpdf2 2.5.2

    # Classe definida aqui para que FPDF esteja no escopo local.
    # Definir no nível do módulo causaria NameError pois FPDF não é importado lá.
    class DiagnosticPDF(FPDF):
        """PDF customizado com cabeçalho e rodapé."""

        def header(self):
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(150, 150, 150)
            self.cell(
                0, 6, "Linux SSH Diagnostics - Relatório Automatizado",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C",
            )
            self.set_text_color(0, 0, 0)
            self.ln(1)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "I", 7)
            self.set_text_color(150, 150, 150)
            self.cell(0, 6, f"P\u00e1gina {self.page_no()}", align="C")

    pdf = DiagnosticPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    lines = markdown_content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i]

        # Cabeçalho H1
        if line.startswith("# "):
            text = _clean_markdown(line[2:])
            pdf.set_font("Helvetica", "B", 18)
            pdf.set_fill_color(30, 30, 60)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(0, 12, text[:80], new_x=XPos.LMARGIN,
                     new_y=YPos.NEXT, fill=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(3)

        # Cabeçalho H2
        elif line.startswith("## "):
            text = _clean_markdown(line[3:])
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_fill_color(220, 230, 245)
            pdf.set_text_color(20, 20, 80)
            pdf.cell(0, 10, text[:80], new_x=XPos.LMARGIN,
                     new_y=YPos.NEXT, fill=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)

        # Cabeçalho H3
        elif line.startswith("### "):
            text = _clean_markdown(line[4:])
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(40, 40, 100)
            pdf.cell(0, 8, text[:80], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)

        # Linha separadora
        elif line.startswith("---"):
            pdf.ln(2)
            pdf.set_draw_color(180, 180, 180)
            pdf.line(pdf.l_margin, pdf.get_y(),
                     pdf.l_margin + pdf.epw, pdf.get_y())
            pdf.ln(3)

        # Bloco de código
        elif line.startswith("```"):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code_lines.append(lines[i])
                i += 1
            if code_lines:
                pdf.set_font("Courier", size=7)
                pdf.set_fill_color(245, 245, 245)
                pdf.set_draw_color(200, 200, 200)
                code_text = "\n".join(code_lines[:40])
                try:
                    pdf.multi_cell(
                        0, 4, _safe_encode(code_text[:1200]), border=1, fill=True
                    )
                except Exception:
                    pass
                pdf.set_font("Helvetica", size=9)
                pdf.ln(2)

        # Linha em branco
        elif not line.strip():
            pdf.ln(2)

        # Linha de tabela Markdown
        elif line.startswith("|"):
            _render_table_line(pdf, line)
            pdf.set_x(pdf.l_margin)  # garante reset do X após células de tabela

        # Citação blockquote
        elif line.startswith("> "):
            text = _clean_markdown(line[2:])
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_fill_color(240, 248, 255)
            try:
                pdf.multi_cell(0, 6, _safe_encode(text[:300]), fill=True)
            except Exception:
                pass
            pdf.set_font("Helvetica", size=9)
            pdf.ln(1)

        # Texto normal (bold inline)
        else:
            text = _clean_markdown(line)
            if text.strip():
                pdf.set_font("Helvetica", size=9)
                try:
                    pdf.multi_cell(0, 5, _safe_encode(text[:400]))
                except Exception:
                    pass

        i += 1

    pdf.output(str(output_path))
    logger.debug(f"PDF salvo em: {output_path}")


def _clean_markdown(text: str) -> str:
    """Remove marcações Markdown simples para renderização em PDF."""
    # Remove bold/italic
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\*(.+?)\*", r"\1", text)
    # Remove inline code
    text = re.sub(r"`(.+?)`", r"\1", text)
    # Remove links
    text = re.sub(r"\[(.+?)\]\(.+?\)", r"\1", text)
    # Remove apenas emojis/símbolos acima de U+00FF; preserva latin-1 completo (ã, ç, é, â…)
    text = re.sub(r"[^\x00-\xFF]", "", text)
    return text.strip()


def _safe_encode(text: str) -> str:
    """Garante que o texto é seguro para fpdf2 (remove não-ASCII)."""
    return text.encode("latin-1", "replace").decode("latin-1")


def _render_table_line(pdf, line: str) -> None:
    """Renderiza uma linha de tabela Markdown como células PDF."""
    # Pula linhas de separação (|---|---|)
    if re.match(r"\|[\s\-:]+\|", line):
        return

    cells = [c.strip() for c in line.strip("|").split("|")]
    if not cells:
        return

    pdf.set_font("Helvetica", size=8)
    # Usa largura efetiva real do PDF (epw) em vez de 180mm fixo
    col_width = max(pdf.epw / max(len(cells), 1), 15)  # mínimo 15mm por coluna
    for cell in cells:
        text = _clean_markdown(cell)[:40]
        try:
            pdf.cell(col_width, 6, _safe_encode(text), border=1)
        except Exception:
            try:
                pdf.cell(col_width, 6, "?", border=1)
            except Exception:
                pass
    pdf.ln()
