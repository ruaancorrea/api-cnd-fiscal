# Dockerfile (VERSÃO FINAL E COMPLETA)

# Estágio 1: Build - Instala dependências do sistema e do Python
FROM python:3.11-slim-bookworm as builder

# Instala o SQLite e outras ferramentas de build no sistema operacional
# Esta é a parte que resolve o erro 'libsqlite3.so.0'
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    libsqlite3-dev \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# Cria um ambiente virtual
WORKDIR /app
RUN python -m venv .venv

# Copia o arquivo de dependências e instala os pacotes Python
COPY requirements.txt ./
RUN .venv/bin/pip install --no-cache-dir -r requirements.txt

# Estágio 2: Final - Cria a imagem final, mais leve
FROM python:3.11-slim-bookworm

# Instala o pacote do sistema SQLite (apenas o necessário para rodar)
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
 && rm -rf /var/lib/apt/lists/*

# Define o diretório de trabalho
WORKDIR /app

# Copia o ambiente virtual com os pacotes instalados do estágio de build
COPY --from=builder /app/.venv .venv/

# Copia todo o código da sua aplicação
COPY . .

# Expõe a porta que a aplicação vai usar
EXPOSE 8080