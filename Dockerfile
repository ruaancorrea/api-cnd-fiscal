# Dockerfile (VERSÃO FINAL E CORRETA)

# Estágio 1: Build - Instala dependências do sistema e do Python
FROM python:3.11-slim-bookworm as builder

# Instala a biblioteca do SQLite e ferramentas de build
# Esta é a correção: usamos o pacote libsqlite3-0
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
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

# Instala a biblioteca do SQLite (apenas o necessário para rodar)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
 && rm -rf /var/lib/apt/lists/*

# Define o diretório de trabalho
WORKDIR /app

# Copia o ambiente virtual com os pacotes instalados do estágio de build
COPY --from=builder /app/.venv .venv/

# Copia todo o código da sua aplicação
COPY . .

# Expõe a porta que a aplicação vai usar
EXPOSE 8080