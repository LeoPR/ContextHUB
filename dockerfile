FROM python:3.13-slim

WORKDIR /app

# Instala dependências do sistema e limpa cache para imagem mais enxuta
RUN apt-get update && \
    apt-get install -y --no-install-recommends sqlite3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copia requirements.txt apenas para /tmp para instalação dos pacotes
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Variáveis de ambiente
ENV DB_PATH=app.db
ENV PORT=8080

EXPOSE 8080

# Executa o script de criação do banco e inicia o app usando a pasta montada
CMD ["sh", "-c", "python3 tools/db_apply_sql.py && python3 app.py"]