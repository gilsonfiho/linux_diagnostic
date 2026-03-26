FROM python:3.12-slim

WORKDIR /app

# Instala dependências de runtime primeiro (camada cacheável)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código fonte
COPY main.py setup.py ./
COPY src/ ./src/

# Diretório de saída — monte como volume para persistir os relatórios
RUN mkdir -p /app/reports

ENTRYPOINT ["python", "main.py"]
