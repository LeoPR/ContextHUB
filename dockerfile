FROM python:3.13-slim

WORKDIR /app

# Copia dependências e instala
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação
#COPY . .

# Porta usada pela aplicação dentro do container
ENV PORT=8080
EXPOSE 8080

# Comando para iniciar a aplicação
CMD ["python", "app.py"]