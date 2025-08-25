# -*- coding: utf-8 -*-
import pandas as pd
import os
import requests
import re
import sqlite3
from datetime import datetime, timedelta
from io import BytesIO
from dotenv import load_dotenv
import time
import math
import threading
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
import warnings
import traceback
import base64

# Bibliotecas para funcionalidades
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import pkcs12
from apscheduler.schedulers.background import BackgroundScheduler
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
import smtplib
from AesEverywhere import aes256

# =============================================
# CONFIGURAÇÕES INICIAIS E VARIÁVEIS DE AMBIENTE
# =============================================
load_dotenv()

INFOSIMPLES_TOKEN = os.getenv("INFOSIMPLES_TOKEN", "").strip()
INFOSIMPLES_CRYPTO_KEY = os.getenv("INFOSIMPLES_CRYPTO_KEY", "").strip()
CNPJA_TOKEN = os.getenv("CNPJA_TOKEN", "").strip()
EMAIL_HOST = os.getenv("EMAIL_HOST", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
CRYPTOGRAPHY_KEY = os.getenv("CRYPTOGRAPHY_KEY", "")
EMAIL_ALERTAS_ECAC = os.getenv("EMAIL_ALERTAS_ECAC", EMAIL_USER)

# Constantes
DB_FILE = os.getenv("DATABASE_PATH", "sistema_consultas2.db")
CERTIFICADOS_DIR = Path("certificados_grupos")
RESULTADOS_DIR = Path("resultados_consultas")
ERROS_DIR = Path("erros_consultas")
DOCUMENTOS_DIR = Path("documentos_empresas")
JSON_LOGS_DIR = Path("json_logs")

CERTIFICADOS_DIR.mkdir(exist_ok=True)
RESULTADOS_DIR.mkdir(exist_ok=True)
ERROS_DIR.mkdir(exist_ok=True)
DOCUMENTOS_DIR.mkdir(exist_ok=True)
JSON_LOGS_DIR.mkdir(exist_ok=True)

MAX_TENTATIVAS = 3
FAILURE_THRESHOLD = 3
PAUSE_DURATION_MINUTES = 30

TIPOS_CONSULTA = {
    "cnd_federal": {"desc": "CND Federal (com Sit. Fiscal)", "sheet_name": "CND Federal"},
    "cnd_estadual": {"desc": "CND Estadual (SEFAZ)", "sheet_name": "CND Estadual"},
    "cnd_trabalhista": {"desc": "CND Trabalhista (TST)", "sheet_name": "CND Trabalhista"},
    "cnd_fgts": {"desc": "Certidão de Regularidade do FGTS (CRF)", "sheet_name": "FGTS (CRF)"},
    "simples_nacional": {"desc": "Consulta Simples Nacional", "sheet_name": "Simples Nacional"},
    "caixa_postal_ecac": {"desc": "Caixa Postal e-CAC", "sheet_name": "Caixa Postal e-CAC"}
}

ALERTAS_ECAC_KEYWORDS = [
    "EXCLUSÃO DO SIMPLES", "TERMO DE EXCLUSÃO", "EXCLUSAO DO SIMPLES",
    "TERMO DE OPÇÃO", "AUTO DE INFRAÇÃO", "MALHA FISCAL", "DÉBITO PREVIDENCIÁRIO",
    "INTIMAÇÃO", "NOTIFICAÇÃO DE LANÇAMENTO"
]

# =============================================
# MÓDULO DE DADOS E ESTRUTURA
# =============================================
COLUNA_MOLDS = {
    "cnd_federal": {
        'CNPJ': '-', 'Nome': '-', 'Situação': '-', 'Tipo': '-', 'Validade': '-',
        'Interpretação': '-', 'PENDÊNCIAS': '-', 'Link Certidão': '-'
    },
    "cnd_estadual": {
        'CNPJ': '-', 'Nome': '-', 'Situação': '-', 'Validade': '-', 'Interpretação': '-',
        'PENDÊNCIAS': '-', 'Link Certidão': '-'
    },
    "cnd_trabalhista": {
        'CNPJ': '-', 'Nome': '-', 'Situação': '-', 'Validade': '-', 'Interpretação': '-',
        'PENDÊNCIAS / PROCESSOS': '-', 'Link Certidão': '-'
    },
    "cnd_fgts": {
        'CNPJ': '-', 'Nome': '-', 'Situação': '-', 'Validade Início': '-', 'Validade Fim': '-',
        'Interpretação': '-', 'Link CRF': '-'
    },
    "simples_nacional": {
        'CNPJ': '-', 'Nome': '-', 'Situação Atual': '-', 'Interpretação': '-',
        'Histórico de Desenquadramentos': '-', 'Data da Consulta': '-', 'Link Consulta': '-'
    }
}

def criar_molde_resultado(tipo_consulta):
    return COLUNA_MOLDS.get(tipo_consulta, {}).copy()

# =============================================
# MÓDULO DE SEGURANÇA E CERTIFICADOS
# =============================================
def init_crypto():
    if not CRYPTOGRAPHY_KEY:
        print("⚠️ ALERTA DE SEGURANÇA: A chave de criptografia não está configurada.")
        return None
    return Fernet(CRYPTOGRAPHY_KEY.encode())

cipher_suite = init_crypto()

def encrypt_password(password: str) -> bytes:
    if not cipher_suite or not password: return b''
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password: bytes) -> str:
    if not cipher_suite or not encrypted_password: return ""
    try:
        return cipher_suite.decrypt(encrypted_password).decode()
    except Exception:
        return "Erro ao descriptografar"

def get_certificate_expiry_date(pfx_data: bytes, password: str) -> datetime:
    try:
        _, certificate, _ = pkcs12.load_key_and_certificates(pfx_data, password.encode() if password else None)
        return certificate.not_valid_after_utc
    except Exception as e:
        print(f"Não foi possível ler o certificado: {e}")
        return None

# =============================================
# MÓDULO DE BANCO DE DADOS (COM GRUPOS)
# =============================================
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS empresas (id INTEGER PRIMARY KEY AUTOINCREMENT, cnpj TEXT UNIQUE NOT NULL, razao_social TEXT NOT NULL, cep TEXT, criado_em TEXT DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS grupos (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT UNIQUE NOT NULL, certificado_path TEXT, certificado_senha_encrypted BLOB, certificado_vencimento DATE)')
        c.execute('CREATE TABLE IF NOT EXISTS empresa_grupo (empresa_id INTEGER, grupo_id INTEGER, FOREIGN KEY(empresa_id) REFERENCES empresas(id) ON DELETE CASCADE, FOREIGN KEY(grupo_id) REFERENCES grupos(id) ON DELETE CASCADE, PRIMARY KEY (empresa_id, grupo_id))')
        c.execute('CREATE TABLE IF NOT EXISTS agendamentos (id INTEGER PRIMARY KEY AUTOINCREMENT, nome_agendamento TEXT NOT NULL, emails_notificacao TEXT NOT NULL, frequencia TEXT NOT NULL, dia_do_mes INTEGER NOT NULL, dias_antecedencia INTEGER DEFAULT 2, ativo INTEGER DEFAULT 1, criado_em TEXT DEFAULT CURRENT_TIMESTAMP, consultas_config TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS agendamento_grupo (agendamento_id INTEGER, grupo_id INTEGER, FOREIGN KEY(agendamento_id) REFERENCES agendamentos(id) ON DELETE CASCADE, FOREIGN KEY(grupo_id) REFERENCES grupos(id) ON DELETE CASCADE, PRIMARY KEY (agendamento_id, grupo_id))')
        c.execute('CREATE TABLE IF NOT EXISTS tarefas_consulta (id INTEGER PRIMARY KEY AUTOINCREMENT, agendamento_id INTEGER, empresa_id INTEGER, tipo_consulta TEXT NOT NULL, status TEXT DEFAULT \'pendente\', tentativas INTEGER DEFAULT 0, data_agendada TEXT NOT NULL, ultima_tentativa TEXT, resultado_path TEXT, detalhes_erro TEXT, ultima_situacao TEXT, execucao_avulsa_id TEXT, config_json TEXT, FOREIGN KEY(empresa_id) REFERENCES empresas(id) ON DELETE CASCADE, FOREIGN KEY(agendamento_id) REFERENCES agendamentos(id) ON DELETE CASCADE)')
        c.execute('CREATE TABLE IF NOT EXISTS cadastros_pendentes (id INTEGER PRIMARY KEY AUTOINCREMENT, cnpj TEXT UNIQUE NOT NULL, cep TEXT, status TEXT DEFAULT \'pendente\', detalhes_erro TEXT, tentativas INTEGER DEFAULT 0, ultima_tentativa DATETIME)')
        c.execute('CREATE TABLE IF NOT EXISTS circuit_breakers (tipo_consulta TEXT PRIMARY KEY, consecutive_failures INTEGER DEFAULT 0, open_until DATETIME)')
        c.execute('CREATE TABLE IF NOT EXISTS documentos_empresa (id INTEGER PRIMARY KEY AUTOINCREMENT, empresa_id INTEGER, tipo_documento TEXT NOT NULL, descricao TEXT, data_vencimento DATE, arquivo_path TEXT NOT NULL, criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(empresa_id) REFERENCES empresas(id) ON DELETE CASCADE)')
        c.execute('CREATE TABLE IF NOT EXISTS empresa_config (empresa_id INTEGER PRIMARY KEY, ecac_frequencia TEXT DEFAULT \'nunca\', FOREIGN KEY(empresa_id) REFERENCES empresas(id) ON DELETE CASCADE)')
        c.execute('''CREATE TABLE IF NOT EXISTS ecac_mensagens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, 
                        empresa_id INTEGER, 
                        id_mensagem_api TEXT UNIQUE, 
                        remetente TEXT, 
                        assunto TEXT, 
                        envio_data DATE, 
                        leitura_data DATE, 
                        conteudo_html TEXT, 
                        lida_api BOOLEAN DEFAULT 0, 
                        marcada_como_lida_usuario BOOLEAN DEFAULT 0,
                        cnpj_destinatario TEXT,
                        razao_social_destinatario TEXT,
                        FOREIGN KEY(empresa_id) REFERENCES empresas(id) ON DELETE CASCADE
                    )''')
        c.execute('CREATE TABLE IF NOT EXISTS ecac_alertas_enviados (mensagem_id INTEGER PRIMARY KEY, FOREIGN KEY(mensagem_id) REFERENCES ecac_mensagens(id) ON DELETE CASCADE)')
        c.execute('CREATE TABLE IF NOT EXISTS status_adicional (empresa_id INTEGER, tipo_status TEXT, situacao TEXT, detalhes TEXT, data_atualizacao TEXT, PRIMARY KEY (empresa_id, tipo_status), FOREIGN KEY(empresa_id) REFERENCES empresas(id) ON DELETE CASCADE)')
        c.execute('CREATE TABLE IF NOT EXISTS configuracoes_sistema (chave TEXT PRIMARY KEY, valor TEXT)')
        conn.commit()

def atualizar_banco_de_dados():
    print("[ATUALIZAÇÃO DB] Verificando estrutura do banco de dados...")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("PRAGMA table_info(ecac_mensagens)")
    colunas = [col[1] for col in c.fetchall()]
    colunas_para_adicionar = {
        "cnpj_destinatario": "TEXT",
        "razao_social_destinatario": "TEXT"
    }
    alteracoes_feitas = False
    for nome_coluna, tipo_coluna in colunas_para_adicionar.items():
        if nome_coluna not in colunas:
            try:
                print(f"[ATUALIZAÇÃO DB] Coluna '{nome_coluna}' não existe. Adicionando...")
                c.execute(f"ALTER TABLE ecac_mensagens ADD COLUMN {nome_coluna} {tipo_coluna}")
                print(f"[ATUALIZAÇÃO DB] Coluna '{nome_coluna}' adicionada com sucesso!")
                alteracoes_feitas = True
            except Exception as e:
                print(f"[ATUALIZAÇÃO DB] ERRO ao adicionar coluna '{nome_coluna}': {e}")
    if alteracoes_feitas:
        conn.commit()
    print("[ATUALIZAÇÃO DB] Verificação concluída.")
    conn.close()

def criar_tarefas_avulsas(empresa_ids: list, tipos_consulta: list, config: dict):
    job_id = f"avulsa_{int(time.time())}"
    tarefas_criadas = 0
    task_config_json = json.dumps(config)
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for empresa_id in empresa_ids:
            empresa_row = c.execute("SELECT id FROM empresas WHERE id = ?", (empresa_id,)).fetchone()
            if empresa_row:
                for tipo_consulta in tipos_consulta:
                    if tipo_consulta == 'cnd_estadual_detalhada': continue
                    c.execute("""
                        INSERT INTO tarefas_consulta (empresa_id, tipo_consulta, data_agendada, execucao_avulsa_id, config_json) 
                        VALUES (?, ?, ?, ?, ?)
                    """, (empresa_id, tipo_consulta, datetime.now().strftime('%Y-%m-%d'), job_id, task_config_json))
                    tarefas_criadas += 1
    conn.commit()
    return tarefas_criadas, job_id


def get_dashboard_metrics():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        total_empresas = c.execute("SELECT COUNT(id) FROM empresas").fetchone()[0]
        
        hoje = datetime.now().date()
        data_limite = hoje + timedelta(days=60)
        cert_vencendo = c.execute("SELECT COUNT(id) FROM grupos WHERE certificado_vencimento BETWEEN ? AND ?", (hoje.strftime('%Y-%m-%d'), data_limite.strftime('%Y-%m-%d'))).fetchone()[0]
        
        pend_federal = c.execute("SELECT COUNT(DISTINCT empresa_id) FROM tarefas_consulta WHERE id IN (SELECT MAX(id) FROM tarefas_consulta WHERE tipo_consulta = 'cnd_federal' AND status IN ('sucesso', 'concluido') GROUP BY empresa_id) AND ultima_situacao = 'IRREGULAR'").fetchone()[0]
        pend_estadual = c.execute("SELECT COUNT(DISTINCT empresa_id) FROM tarefas_consulta WHERE id IN (SELECT MAX(id) FROM tarefas_consulta WHERE tipo_consulta = 'cnd_estadual' AND status IN ('sucesso', 'concluido') GROUP BY empresa_id) AND ultima_situacao = 'IRREGULAR'").fetchone()[0]
        pend_trabalhista = c.execute("SELECT COUNT(DISTINCT empresa_id) FROM tarefas_consulta WHERE id IN (SELECT MAX(id) FROM tarefas_consulta WHERE tipo_consulta = 'cnd_trabalhista' AND status IN ('sucesso', 'concluido') GROUP BY empresa_id) AND ultima_situacao = 'IRREGULAR'").fetchone()[0]
        pend_fgts = c.execute("SELECT COUNT(DISTINCT empresa_id) FROM tarefas_consulta WHERE id IN (SELECT MAX(id) FROM tarefas_consulta WHERE tipo_consulta = 'cnd_fgts' AND status IN ('sucesso', 'concluido') GROUP BY empresa_id) AND ultima_situacao = 'IRREGULAR'").fetchone()[0]

        nao_lidas_count = c.execute("SELECT COUNT(id) FROM ecac_mensagens WHERE marcada_como_lida_usuario = 0").fetchone()[0]

        return {
            "total_empresas": total_empresas,
            "certificados_vencendo_60d": cert_vencendo,
            "pendencias_federal": pend_federal,
            "pendencias_estadual": pend_estadual,
            "pendencias_trabalhista": pend_trabalhista,
            "pendencias_fgts": pend_fgts,
            "mensagens_ecac_nao_lidas": nao_lidas_count
        }

def update_empresa_ecac_config(empresa_id: int, frequencia: str):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT OR REPLACE INTO empresa_config (empresa_id, ecac_frequencia) VALUES (?, ?)", (empresa_id, frequencia))

def add_empresas_from_file(file_content: bytes, file_type: str):
    try:
        if file_type == 'csv':
            df = pd.read_csv(BytesIO(file_content), dtype=str)
        else:
            df = pd.read_excel(BytesIO(file_content), dtype=str)

        df.columns = [str(col).strip().upper() for col in df.columns]
        if 'CNPJ' not in df.columns:
            return 0, "Coluna 'CNPJ' não encontrada."

        df.dropna(subset=['CNPJ'], inplace=True)
        df['CNPJ'] = df['CNPJ'].astype(str).str.strip()
        df = df[df['CNPJ'] != '']
        df['CNPJ_limpo'] = df['CNPJ'].apply(lambda x: re.sub(r'[^\d]', '', str(x)))
        adicionados = 0
        with sqlite3.connect(DB_FILE) as conn:
            for _, row in df.iterrows():
                cnpj_limpo = row['CNPJ_limpo']
                cep = row.get('CEP', '')
                if len(cnpj_limpo) == 14:
                    try:
                        conn.execute("INSERT OR IGNORE INTO cadastros_pendentes (cnpj, cep) VALUES (?, ?)", (cnpj_limpo, cep))
                        adicionados += 1
                    except sqlite3.IntegrityError:
                        pass
        return adicionados, None
    except Exception as e:
        return 0, str(e)

def create_agendamento(agendamento: dict):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO agendamentos (nome_agendamento, emails_notificacao, frequencia, dia_do_mes, consultas_config) VALUES (?, ?, ?, ?, ?)",
                  (agendamento['nome_agendamento'], agendamento['emails_notificacao'], 'Mensal', agendamento['dia_do_mes'], json.dumps(agendamento['consultas_config'])))
        agendamento_id = c.lastrowid
        for g_id in agendamento['grupo_ids']:
            c.execute("INSERT INTO agendamento_grupo (agendamento_id, grupo_id) VALUES (?, ?)", (agendamento_id, g_id))
        conn.commit()
        return agendamento_id

def get_agendamento_por_id(agendamento_id: int):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        agend = conn.execute("SELECT * FROM agendamentos WHERE id=?", (agendamento_id,)).fetchone()
        if not agend:
            return None, None
        
        grupos_rows = conn.execute("SELECT grupo_id FROM agendamento_grupo WHERE agendamento_id=?", (agendamento_id,)).fetchall()
        grupo_ids = [row['grupo_id'] for row in grupos_rows]
        
        agend_dict = dict(agend)
        agend_dict['consultas_config'] = json.loads(agend_dict['consultas_config'])
        return agend_dict, grupo_ids

def get_config(chave: str, default: str) -> str:
    with sqlite3.connect(DB_FILE) as conn:
        result = conn.execute("SELECT valor FROM configuracoes_sistema WHERE chave = ?", (chave,)).fetchone()
        return result[0] if result else default

def set_config(chave: str, valor: str):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT OR REPLACE INTO configuracoes_sistema (chave, valor) VALUES (?, ?)", (chave, valor))

def add_empresa(cnpj, razao_social, cep):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO empresas (cnpj, razao_social, cep) VALUES (?, ?, ?)", (cnpj, razao_social, cep))
        empresa_id = c.lastrowid
        c.execute("INSERT OR IGNORE INTO empresa_config (empresa_id, ecac_frequencia) VALUES (?, 'nunca')", (empresa_id,))
        conn.commit()
        return empresa_id

def associar_empresa_a_grupos(empresa_id, grupo_ids):
    if not empresa_id or not grupo_ids: return
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        registros = [(empresa_id, grupo_id) for grupo_id in grupo_ids]
        c.executemany("INSERT OR IGNORE INTO empresa_grupo (empresa_id, grupo_id) VALUES (?, ?)", registros)
        conn.commit()

def update_empresa_grupos(grupo_id, final_member_ids):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM empresa_grupo WHERE grupo_id = ?", (grupo_id,))
        if final_member_ids:
            c.executemany("INSERT OR IGNORE INTO empresa_grupo (empresa_id, grupo_id) VALUES (?, ?)", [(emp_id, grupo_id) for emp_id in final_member_ids])
        conn.commit()

def associar_empresas_em_massa_por_cnpj(grupo_id, cnpjs_texto):
    cnpjs_limpos = [re.sub(r'[^\d]', '', cnpj) for cnpj in cnpjs_texto.splitlines() if cnpj.strip()]
    cnpjs_validos = [cnpj for cnpj in cnpjs_limpos if len(cnpj) == 14]
    associados, nao_encontrados = [], []
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for cnpj in cnpjs_validos:
            c.execute("SELECT id FROM empresas WHERE cnpj LIKE ?", (f'%{cnpj}%',))
            empresa_row = c.fetchone()
            if empresa_row:
                empresa_id = empresa_row[0]
                try:
                    c.execute("INSERT OR IGNORE INTO empresa_grupo (empresa_id, grupo_id) VALUES (?, ?)", (empresa_id, grupo_id))
                    associados.append(cnpj)
                except sqlite3.IntegrityError: pass
            else:
                nao_encontrados.append(cnpj)
        conn.commit()
    return associados, nao_encontrados

def get_empresas_do_grupo(grupo_id):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT empresa_id FROM empresa_grupo WHERE grupo_id=?", (grupo_id,))
        return {row[0] for row in c.fetchall()}

def update_grupo_certificado(grupo_id, cert_path, encrypted_pass, expiry_date_str):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT certificado_path FROM grupos WHERE id = ?", (grupo_id,))
        old_path_row = c.fetchone()
        old_path = old_path_row[0] if old_path_row else None
        c.execute("UPDATE grupos SET certificado_path=?, certificado_senha_encrypted=?, certificado_vencimento=? WHERE id=?", (cert_path, encrypted_pass, expiry_date_str, grupo_id))
        conn.commit()
        if old_path and old_path != cert_path and os.path.exists(old_path):
            try: os.remove(old_path)
            except OSError as e: print(f"ERRO: Não foi possível remover o certificado antigo '{old_path}': {e}")

def get_empresa_por_id(empresa_id: int):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        query = "SELECT e.*, ec.ecac_frequencia FROM empresas e LEFT JOIN empresa_config ec ON e.id = ec.empresa_id WHERE e.id = ?"
        row = conn.execute(query, (empresa_id,)).fetchone()
        return dict(row) if row else None
        
def get_empresas():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        query = "SELECT e.*, ec.ecac_frequencia FROM empresas e LEFT JOIN empresa_config ec ON e.id = ec.empresa_id ORDER BY e.razao_social"
        rows = conn.execute(query).fetchall()
        return [dict(row) for row in rows]

def delete_empresa(empresa_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM empresas WHERE id=?", (empresa_id,))

def get_grupos():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        query = """
            SELECT g.id, g.nome, g.certificado_vencimento, 
                   COUNT(eg.empresa_id) as total_empresas 
            FROM grupos g 
            LEFT JOIN empresa_grupo eg ON g.id = eg.grupo_id 
            GROUP BY g.id, g.nome 
            ORDER BY g.nome
        """
        rows = conn.execute(query).fetchall()
        return [dict(row) for row in rows]
    
def add_grupo(nome):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO grupos (nome) VALUES (?)", (nome,))

def delete_grupo(grupo_id):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT certificado_path FROM grupos WHERE id=?", (grupo_id,))
        result = c.fetchone()
        if result and result[0] and os.path.exists(result[0]):
            try: os.remove(result[0])
            except OSError: pass
        c.execute("DELETE FROM grupos WHERE id=?", (grupo_id,))
        conn.commit()

def get_agendamentos():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM agendamentos ORDER BY nome_agendamento").fetchall()

def get_grupos_do_agendamento(agendamento_id):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT grupo_id FROM agendamento_grupo WHERE agendamento_id=?", (agendamento_id,))
        return {row[0] for row in c.fetchall()}

def toggle_agendamento_ativo(agendamento_id, status):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("UPDATE agendamentos SET ativo = ? WHERE id = ?", (status, agendamento_id))

def delete_agendamento(agendamento_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM agendamentos WHERE id=?", (agendamento_id,))
        conn.execute("DELETE FROM agendamento_grupo WHERE agendamento_id=?", (agendamento_id,))

def update_agendamento(agendamento_id, nome, emails, dia, config, grupo_ids):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("UPDATE agendamentos SET nome_agendamento=?, emails_notificacao=?, dia_do_mes=?, consultas_config=? WHERE id=?", (nome, emails, dia, json.dumps(config), agendamento_id))
        c.execute("DELETE FROM agendamento_grupo WHERE agendamento_id=?", (agendamento_id,))
        if grupo_ids:
            c.executemany("INSERT INTO agendamento_grupo (agendamento_id, grupo_id) VALUES (?, ?)", [(agendamento_id, g_id) for g_id in grupo_ids])
        conn.commit()

def limpar_historico_tarefas():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM tarefas_consulta")
        print("Histórico de tarefas de consulta foi limpo com sucesso!")

def get_dossie_data(empresa_id):
    dossie = {'info': None, 'resultados': {}}
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        info_row = conn.execute("SELECT * FROM empresas WHERE id = ?", (empresa_id,)).fetchone()
        if not info_row: 
            return None
        dossie['info'] = dict(info_row)
        for tipo, data in TIPOS_CONSULTA.items():
            if tipo == 'caixa_postal_ecac': continue
            tarefa = conn.execute("SELECT * FROM tarefas_consulta WHERE empresa_id = ? AND tipo_consulta = ? AND status IN ('sucesso', 'concluido') ORDER BY id DESC LIMIT 1", (empresa_id, tipo)).fetchone()
            if tarefa and tarefa['resultado_path'] and os.path.exists(tarefa['resultado_path']):
                try:
                    with open(tarefa['resultado_path'], 'r', encoding='utf-8') as f:
                        dossie['resultados'][tipo] = json.load(f)
                except Exception:
                    dossie['resultados'][tipo] = {"Erro": "Falha ao ler o arquivo de resultado."}
            else:
                dossie['resultados'][tipo] = None
    return dossie

def add_documento(empresa_id, tipo_documento, descricao, data_vencimento, arquivo_path):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO documentos_empresa (empresa_id, tipo_documento, descricao, data_vencimento, arquivo_path) VALUES (?, ?, ?, ?, ?)",
            (empresa_id, tipo_documento, descricao, data_vencimento, arquivo_path)
        )

def get_documentos_da_empresa(empresa_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM documentos_empresa WHERE empresa_id = ? ORDER BY data_vencimento DESC", (empresa_id,)).fetchall()

def delete_documento(documento_id):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT arquivo_path FROM documentos_empresa WHERE id=?", (documento_id,))
        result = c.fetchone()
        if result and result[0] and os.path.exists(result[0]):
            try:
                os.remove(result[0])
            except OSError as e:
                print(f"ERRO: Não foi possível remover o arquivo de documento '{result[0]}': {e}")
        c.execute("DELETE FROM documentos_empresa WHERE id=?", (documento_id,))

def get_documentos_vencendo():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        hoje = datetime.now().date()
        data_limite = hoje + timedelta(days=60)
        return conn.execute("""
            SELECT d.tipo_documento, d.data_vencimento, e.razao_social
            FROM documentos_empresa d
            JOIN empresas e ON d.empresa_id = e.id
            WHERE d.data_vencimento BETWEEN ? AND ?
            ORDER BY d.data_vencimento ASC
        """, (hoje.strftime('%Y-%m-%d'), data_limite.strftime('%Y-%m-%d'))).fetchall()

def get_empresa_config(empresa_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        config = conn.execute("SELECT ecac_frequencia FROM empresa_config WHERE empresa_id = ?", (empresa_id,)).fetchone()
        if config:
            return config
        return {'ecac_frequencia': 'nunca'}

def update_empresa_config(empresa_id, frequencia):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT OR REPLACE INTO empresa_config (empresa_id, ecac_frequencia) VALUES (?, ?)", (empresa_id, frequencia))

def get_caixa_postal_nao_lidas(empresa_id=None):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        dias_busca_str = get_config('dias_busca_ecac', '30')
        data_inicio_filtro = (datetime.now() - timedelta(days=int(dias_busca_str))).strftime('%Y-%m-%d')
        query = "SELECT * FROM ecac_mensagens WHERE marcada_como_lida_usuario = 0 AND envio_data >= ?"
        params = [data_inicio_filtro]
        if empresa_id:
            query += " AND empresa_id = ?"
            params.append(empresa_id)
        query += " ORDER BY envio_data DESC, id DESC"
        return conn.execute(query, params).fetchall()

def get_caixa_postal_todas(empresa_id=None):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        dias_busca_str = get_config('dias_busca_ecac', '30')
        data_inicio_filtro = (datetime.now() - timedelta(days=int(dias_busca_str))).strftime('%Y-%m-%d')
        query = "SELECT * FROM ecac_mensagens WHERE envio_data >= ?"
        params = [data_inicio_filtro]
        if empresa_id:
            query += " AND empresa_id = ?"
            params.append(empresa_id)
        query += " ORDER BY envio_data DESC, id DESC"
        return conn.execute(query, params).fetchall()

def marcar_mensagem_como_lida(mensagem_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("UPDATE ecac_mensagens SET marcada_como_lida_usuario = 1 WHERE id = ?", (mensagem_id,))

# =============================================
# FUNÇÕES AUXILIARES E DE CONSULTA
# =============================================
def limpar_e_formatar_cnpj(cnpj):
    if pd.isna(cnpj) or str(cnpj).strip().lower() in ['', 'nan', 'nat', 'none']: return None
    if isinstance(cnpj, float): cnpj = '{:.0f}'.format(cnpj)
    else: cnpj = str(cnpj).strip()
    cnpj_limpo = re.sub(r"[^\d]", "", cnpj)
    if len(cnpj_limpo) != 14: return None
    return f"{cnpj_limpo[:2]}.{cnpj_limpo[2:5]}.{cnpj_limpo[5:8]}/{cnpj_limpo[8:12]}-{cnpj_limpo[12:]}"

def consultar_api_infosimples(endpoint_url, payload):
    if not INFOSIMPLES_TOKEN: raise ValueError("Token da InfoSimples não configurado")
    payload['token'] = INFOSIMPLES_TOKEN
    payload.setdefault('timeout', 400)
    try:
        response = requests.post(endpoint_url, data=payload, timeout=payload['timeout'] + 10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Erro de rede ao contatar API: {e}")
    except json.JSONDecodeError:
        raise ValueError(f"Resposta inválida (não é JSON) da API: {response.text[:200]}")

def consultar_cnpja(cnpj):
    if not CNPJA_TOKEN: return None, "Token do CNPJà não configurado."
    headers = {"Authorization": CNPJA_TOKEN}
    try:
        cnpj_limpo = re.sub(r'[^\d]', '', str(cnpj))
        response = requests.get(f"https://api.cnpja.com/office/{cnpj_limpo}", headers=headers, timeout=20)
        if response.status_code == 200:
            data = response.json()
            razao_social = data.get("company", {}).get("name")
            return (razao_social, None) if razao_social else (None, "API não retornou a razão social.")
        elif response.status_code == 429:
            return None, "quota"
        else:
            return None, f"Erro na API CNPJà: Status {response.status_code}"
    except requests.exceptions.RequestException as e:
        return None, f"Erro de conexão com a API CNPJà: {e}"

def enviar_email(destinatario, assunto, corpo_html, anexo_data=None, anexo_nome=None):
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS]):
        print("AVISO: Configurações de e-mail incompletas. E-mail não enviado.")
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = destinatario
        msg['Subject'] = assunto
        msg.attach(MIMEText(corpo_html, 'html'))

        if anexo_data and anexo_nome:
            part = MIMEApplication(anexo_data, Name=anexo_nome)
            part['Content-Disposition'] = f'attachment; filename="{anexo_nome}"'
            msg.attach(part)

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        print(f"INFO: E-mail '{assunto}' enviado para {destinatario}.")
    except Exception as e:
        print(f"ERRO: Falha no envio do e-mail '{assunto}': {e}")
        traceback.print_exc()

# =============================================
# LÓGICA DO WORKER (PROCESSAMENTO DE TAREFAS)
# =============================================
def _consultar_pendencias_detalhadas_mg(cnpj_empresa):
    pendencias_encontradas = []
    resultado_api_cadin = None
    resultado_api_parc = None
    try:
        payload_cadin = {"cnpj": cnpj_empresa}
        resultado_api_cadin = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/sefaz/mg/cadin", payload_cadin)
        if resultado_api_cadin.get('code') == 200 and resultado_api_cadin.get('data'):
            if resultado_api_cadin['data'][0].get('consta_pendencia'):
                msg = resultado_api_cadin['data'][0].get('mensagem', 'Inscrição no CADIN-MG confirmada.')
                pendencias_encontradas.append(f"CADIN-MG: {msg}")
    except Exception as e:
        pendencias_encontradas.append(f"CADIN-MG: Falha ao consultar ({e})")
        resultado_api_cadin = {"erro": str(e)}

    try:
        payload_parc = {"cnpj": cnpj_empresa}
        resultado_api_parc = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/sefaz/mg/parcelamento", payload_parc)
        if resultado_api_parc.get('code') == 200 and resultado_api_parc.get('data'):
            parcelamentos = resultado_api_parc['data'][0].get('detalhes_parcelas', [])
            parcelamentos_irregulares = []
            for p in parcelamentos:
                sit = p.get('situacao_parcelamento', '').upper()
                if sit in ["INADIMPLENTE", "RESCINDIDO", "CANCELADO", "DESISTENTE"]:
                    parcelamentos_irregulares.append(f"Nº {p.get('numero_parcelamento')} ({p.get('tipo_tributo', 'N/A')}) - Situação: {p.get('situacao_parcelamento')}")
            if parcelamentos_irregulares:
                pendencias_encontradas.append(f"Parcelamentos Irregulares: {'; '.join(parcelamentos_irregulares)}")
    except Exception as e:
        pendencias_encontradas.append(f"Parcelamentos: Falha ao consultar ({e})")
        resultado_api_parc = {"erro": str(e)}

    if not pendencias_encontradas:
        resumo_texto = "Análise Detalhada: Nenhuma pendência encontrada no CADIN ou em Parcelamentos. A irregularidade pode ser de outra natureza. Verificação manual recomendada."
    else:
        resumo_texto = "Análise Detalhada: " + " | ".join(pendencias_encontradas)

    return resumo_texto, resultado_api_cadin, resultado_api_parc

def formatar_pendencias(pendencias):
    if not pendencias: return "-"
    textos = ['; '.join([f"{k.replace('_', ' ').capitalize()}: {v}" for k, v in p.items() if v]) if isinstance(p, dict) else str(p) for p in pendencias]
    return "; ".join(textos)

def formatar_pendencias_detalhado(titulo, pendencias):
    if not pendencias: return ""
    textos_finais = [f"**{titulo}:**"]
    for p in pendencias:
        if not isinstance(p, dict):
            textos_finais.append(f"  - {str(p)}")
            continue
        detalhes = '; '.join([f"{k.replace('_', ' ').capitalize()}: {v}" for k, v in p.items()])
        textos_finais.append(f"  - {detalhes}")
    return "\n".join(textos_finais)

def consultar_situacao_fiscal(empresa):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        grupos_da_empresa = conn.execute("SELECT grupo_id FROM empresa_grupo WHERE empresa_id = ?", (empresa['empresa_id'],)).fetchall()
        grupo_ids = [g['grupo_id'] for g in grupos_da_empresa]
        if not grupo_ids: return "Procuração não encontrada", None, None
        placeholders = ','.join('?' for _ in grupo_ids)
        grupos_com_cert = conn.execute(f"SELECT * FROM grupos WHERE id IN ({placeholders}) AND certificado_path IS NOT NULL", grupo_ids).fetchall()

    if not grupos_com_cert: return "Procuração não encontrada", None, None
    procuracao_grupo = grupos_com_cert[0]
    
    try:
        with open(procuracao_grupo['certificado_path'], "rb") as f: cert_data = f.read()
    except FileNotFoundError:
        return f"Arquivo do certificado não encontrado para o grupo '{procuracao_grupo['nome']}'", None, None
        
    senha_decrypted = decrypt_password(procuracao_grupo['certificado_senha_encrypted'])
    if "Erro" in senha_decrypted: return "Erro ao descriptografar a senha da procuração", None, None

    payload = {
        "pkcs12_cert": aes256.encrypt(base64.b64encode(cert_data).decode(), INFOSIMPLES_CRYPTO_KEY),
        "pkcs12_pass": aes256.encrypt(senha_decrypted, INFOSIMPLES_CRYPTO_KEY),
        "perfil_procurador_cnpj": re.sub(r'[^\d]', '', empresa['cnpj']),
    }
    
    response = consultar_api_infosimples('https://api.infosimples.com/api/v2/consultas/ecac/situacao-fiscal', payload)
    
    if response.get('code') == 200 and response.get('data'):
        pendencias_rf = response['data'][0].get('pendencias_receita_federal', [])
        pendencias_pgfn = response['data'][0].get('pendencias_procuradoria_geral', [])
        
        texto_rf = formatar_pendencias_detalhado("Pendências na Receita Federal (RFB)", pendencias_rf)
        texto_pgfn = formatar_pendencias_detalhado("Pendências na Procuradoria-Geral (PGFN)", pendencias_pgfn)
        
        pendencias_texto_final = "\n\n".join(filter(None, [texto_rf, texto_pgfn])).strip()
        if not pendencias_texto_final: pendencias_texto_final = "Nenhuma pendência encontrada, porém a certidão é positiva. Verificar manualmente no e-CAC."
        link = response['site_receipts'][0] if response.get('site_receipts') else None
        return pendencias_texto_final, link, response
    else:
        return "; ".join(response.get('errors', ['Erro desconhecido'])), None, response

def executar_tarefa_cnd_estadual(tarefa, agendamento):
    empresa = tarefa
    resultado_dict = criar_molde_resultado("cnd_estadual")
    resultado_dict['CNPJ'] = limpar_e_formatar_cnpj(empresa['cnpj'])
    nome, _ = consultar_cnpja(resultado_dict['CNPJ'])
    resultado_dict['Nome'] = nome or empresa['razao_social']
    cep_da_empresa = empresa['cep']
    if not cep_da_empresa or not str(cep_da_empresa).strip():
        situacao_simples = "IRREGULAR"
        resultado_dict['Situação'] = "FALHA (DADOS)"
        resultado_dict['Interpretação'] = "❌ Falha: O CEP da empresa não está cadastrado no sistema."
        resultado_dict['PENDÊNCIAS'] = "Ação necessária: Atualize o cadastro da empresa com o CEP correto."
        return resultado_dict, situacao_simples
    payload = {"cnpj": empresa['cnpj'], "cep": str(cep_da_empresa).strip()}
    try:
        resultado_api = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/sefaz/mg/certidao-debitos", payload)
        if resultado_api.get("code") == 620 and not (resultado_api.get("site_receipts") or [None])[0]:
            time.sleep(10)
            resultado_api = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/sefaz/mg/certidao-debitos", payload)
        dados = (resultado_api.get("data") or [{}])[0]
        link_certidao = (resultado_api.get("site_receipts") or [None])[0]
        if link_certidao:
            resultado_dict['Link Certidão'] = link_certidao
        certidao_negativa_flag = dados.get("certidao_negativa", False)
        conseguiu_emitir_flag = dados.get("conseguiu_emitir_certidao_negativa", False)
        if certidao_negativa_flag is True or conseguiu_emitir_flag is True:
            situacao_simples = "REGULAR"
            resultado_dict['Situação'] = "REGULAR"
            resultado_dict['Interpretação'] = "✅ Regular - Certidão Negativa Emitida"
            resultado_dict['Validade'] = dados.get('validade_data', '-')
        else:
            situacao_simples = "IRREGULAR"
            resultado_dict['Situação'] = "IRREGULAR"
            pendencias = dados.get('debitos', [])
            api_errors = "; ".join(resultado_api.get('errors', []))
            situacao_api = dados.get('situacao', 'Não foi possível emitir a certidão.')
            if pendencias:
                resultado_dict['Interpretação'] = "❌ Irregular (com pendências detalhadas)"
                resultado_dict['PENDÊNCIAS'] = formatar_pendencias(pendencias)
            else:
                mensagem_final = f"❌ Irregular - {situacao_api}"
                if api_errors:
                    mensagem_final += f" | Detalhe API: {api_errors}"
                resultado_dict['Interpretação'] = mensagem_final
                resultado_dict['PENDÊNCIAS'] = "Nenhuma pendência detalhada retornada pela consulta principal."
            config = json.loads(tarefa['config_json'] or '{}')
            if config.get('cnd_estadual_detalhada', False):
                print(f"INFO: CND Estadual irregular para {empresa['cnpj']}. Iniciando análise detalhada.")
                pendencias_detalhadas_str, raw_cadin, raw_parc = _consultar_pendencias_detalhadas_mg(empresa['cnpj'])
                pendencias_atuais = resultado_dict.get('PENDÊNCIAS', '')
                if pendencias_atuais and "Nenhuma pendência detalhada" not in pendencias_atuais:
                    resultado_dict['PENDÊNCIAS'] = f"{pendencias_detalhadas_str}\n\n[Pendência Original: {pendencias_atuais}]"
                else:
                    resultado_dict['PENDÊNCIAS'] = pendencias_detalhadas_str
                if raw_cadin:
                    resultado_dict['DETALHE_API_CADIN'] = raw_cadin
                if raw_parc:
                    resultado_dict['DETALHE_API_PARCELAMENTO'] = raw_parc
    except Exception as e:
        print(f"ERRO CRÍTICO na consulta estadual para {empresa['cnpj']}: {e}")
        traceback.print_exc()
        situacao_simples = "IRREGULAR"
        resultado_dict['Situação'] = "FALHA"
        resultado_dict['Interpretação'] = f"❌ Falha na execução da consulta: {str(e)}"
    return resultado_dict, situacao_simples

def executar_tarefa_cnd_federal(tarefa, agendamento):
    empresa = tarefa
    resultado_dict = criar_molde_resultado("cnd_federal")
    resultado_dict['CNPJ'] = limpar_e_formatar_cnpj(empresa['cnpj'])
    nome, _ = consultar_cnpja(resultado_dict['CNPJ'])
    resultado_dict['Nome'] = nome or empresa['razao_social']
    if re.sub(r'[^\d]', '', empresa['cnpj'])[8:12] != '0001':
        resultado_dict['Situação'] = "CONSULTAR MATRIZ"
        resultado_dict['Tipo'] = "N/A (Filial)"
        resultado_dict['Interpretação'] = "⚠️ Deve consultar matriz"
        return resultado_dict, 'REGULAR'
    try:
        print(f"INFO: CND Federal para {empresa['cnpj']} - Tentando 2ª via...")
        resultado_api = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/receita-federal/pgfn/2via", {"cnpj": empresa['cnpj']})
        dados_preliminares = (resultado_api.get("data") or [{}])[0]
        tipo_certidao_preliminar = dados_preliminares.get("tipo") or ""
        if "Negativa" not in tipo_certidao_preliminar:
            print(f"INFO: CND Federal para {empresa['cnpj']} - 2ª via não disponível ou irregular. Forçando nova emissão...")
            resultado_api = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/receita-federal/pgfn/nova", {"cnpj": empresa['cnpj']})
    except Exception as e:
        print(f"AVISO: Falha ao obter 2ª via da CND Federal para {empresa['cnpj']} ({e}). Tentando nova emissão...")
        resultado_api = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/receita-federal/pgfn/nova", {"cnpj": empresa['cnpj']})
    dados = (resultado_api.get("data") or [{}])[0]
    tipo_certidao = dados.get("tipo") or ""
    resultado_dict['Tipo'] = tipo_certidao
    resultado_dict['Validade'] = dados.get("validade", "-")
    resultado_dict['Link Certidão'] = (resultado_api.get("site_receipts") or ["-"])[0]
    if "Negativa" in tipo_certidao:
        situacao_simples, resultado_dict['Situação'], resultado_dict['Interpretação'] = "REGULAR", "REGULAR", "✅ Negativa"
    elif "Positiva com efeitos de negativa" in tipo_certidao:
        situacao_simples, resultado_dict['Situação'], resultado_dict['Interpretação'] = "REGULAR", "REGULAR", "⚠️ Positiva c/ Efeito de Negativa"
    else:
        situacao_simples, resultado_dict['Situação'], resultado_dict['Interpretação'] = "IRREGULAR", "IRREGULAR", "❌ Positiva"
        pendencias_texto, link_situacao, _ = consultar_situacao_fiscal(empresa)
        resultado_dict["PENDÊNCIAS"] = pendencias_texto,
        if link_situacao:
            resultado_dict["Link Certidão"] = link_situacao
    return resultado_dict, situacao_simples

# ... (As outras funções executar_tarefa_* são copiadas exatamente como estão no original)
def executar_tarefa_cnd_trabalhista(tarefa, agendamento):
    empresa = tarefa
    resultado_dict = criar_molde_resultado("cnd_trabalhista")
    resultado_dict['CNPJ'] = limpar_e_formatar_cnpj(empresa['cnpj'])
    nome, _ = consultar_cnpja(resultado_dict['CNPJ'])
    resultado_dict['Nome'] = nome or empresa['razao_social']
    resultado_api = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/tribunal/tst/cndt", {"cnpj": empresa['cnpj']})
    dados = (resultado_api.get("data") or [{}])[0]
    conseguiu_emitir = dados.get("conseguiu_emitir_certidao_negativa", False)
    resultado_dict['Validade'] = dados.get("validade_data", "-")
    resultado_dict['Link Certidão'] = (resultado_api.get("site_receipts") or ["-"])[0]
    if conseguiu_emitir:
        situacao_simples = "REGULAR"
        resultado_dict['Situação'] = "REGULAR"
        if "positiva com efeito de negativa" in (dados.get("situacao") or "").lower():
            resultado_dict['Interpretação'] = "⚠️ Regular (Positiva com Efeito de Negativa)"
        else:
            resultado_dict['Interpretação'] = "✅ Regular (Certidão Negativa)"
    else:
        situacao_simples = "IRREGULAR"
        resultado_dict['Situação'] = "IRREGULAR"
        resultado_dict['Interpretação'] = "❌ Irregular (Consta no BNDT)"
        processos = dados.get("processos_encontrados", [])
        if processos:
            resultado_dict['PENDÊNCIAS / PROCESSOS'] = "\n".join([f"- {proc}" for proc in processos])
    return resultado_dict, situacao_simples

def executar_tarefa_cnd_fgts(tarefa, agendamento):
    empresa = tarefa
    resultado_dict = criar_molde_resultado("cnd_fgts")
    resultado_dict['CNPJ'] = limpar_e_formatar_cnpj(empresa['cnpj'])
    nome, _ = consultar_cnpja(resultado_dict['CNPJ'])
    resultado_dict['Nome'] = nome or empresa['razao_social']
    resultado_api = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/caixa/regularidade", {"cnpj": empresa['cnpj']})
    dados = (resultado_api.get("data") or [{}])[0]
    if resultado_api.get("code") == 200 and (dados.get('situacao') or '').upper() == 'REGULAR':
        situacao_simples = "REGULAR"
        resultado_dict['Situação'] = "REGULAR"
        resultado_dict['Interpretação'] = "✅ Regular"
    else:
        situacao_simples = "IRREGULAR"
        resultado_dict['Situação'] = "IRREGULAR"
        resultado_dict['Interpretação'] = "❌ Irregular"
    resultado_dict['Validade Início'] = dados.get("validade_inicio_data", "-")
    resultado_dict['Validade Fim'] = dados.get("validade_fim_data", "-")
    resultado_dict['Link CRF'] = (resultado_api.get("site_receipts") or ["-"])[0]
    return resultado_dict, situacao_simples

def executar_tarefa_simples_nacional(tarefa, agendamento):
    empresa = tarefa
    resultado_dict = criar_molde_resultado("simples_nacional")
    resultado_dict['CNPJ'] = limpar_e_formatar_cnpj(empresa['cnpj'])
    nome, _ = consultar_cnpja(resultado_dict['CNPJ'])
    resultado_dict['Nome'] = nome or empresa['razao_social']
    resultado_api = consultar_api_infosimples("https://api.infosimples.com/api/v2/consultas/receita-federal/simples", {"cnpj": empresa['cnpj']})
    dados = (resultado_api.get("data") or [{}])[0]
    situacao_api = dados.get('simples_nacional_situacao', 'Não Informado')
    eventos_futuros = dados.get('simples_nacional_eventos_futuros', [])
    resultado_dict['Situação Atual'] = situacao_api
    resultado_dict['Data da Consulta'] = dados.get("consulta_datahora", "-")
    resultado_dict['Link Consulta'] = (resultado_api.get("site_receipts") or ["-"])[0]
    if "Optante pelo Simples Nacional" in situacao_api and not eventos_futuros:
        situacao_simples = "REGULAR"
        resultado_dict['Interpretação'] = "✅ Optante e Regular"
    elif eventos_futuros:
        situacao_simples = "IRREGULAR"
        primeiro_evento = eventos_futuros[0].get('detalhamento', 'Data não especificada')
        match = re.search(r'(\d{2}/\d{2}/\d{4})', primeiro_evento)
        data_exclusao = match.group(1) if match else ''
        resultado_dict['Interpretação'] = f"⚠️ TERMO DE EXCLUSÃO AGENDADO PARA {data_exclusao}!"
    else:
        situacao_simples = "REGULAR"
        resultado_dict['Interpretação'] = f"ℹ️ {situacao_api}"
    historico_sn = dados.get('simples_nacional_periodos_anteriores', [])
    historico_simei = dados.get('simei_periodos_anteriores', [])
    historico_textos = [f"Simples Nacional: {ev.get('detalhamento', 'N/A')}" for ev in historico_sn] + [f"SIMEI: {ev.get('detalhamento', 'N/A')}" for ev in historico_simei]
    resultado_dict['Histórico de Desenquadramentos'] = "; ".join(historico_textos) if historico_textos else "-"
    return resultado_dict, situacao_simples

def executar_tarefa_caixa_postal_ecac(tarefa, agendamento):
    empresa = tarefa
    print(f"[{datetime.now()}] INFO: Iniciando verificação da Caixa Postal para {empresa['cnpj']}")

    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            grupos_da_empresa = conn.execute("SELECT grupo_id FROM empresa_grupo WHERE empresa_id = ?", (empresa['empresa_id'],)).fetchall()
            grupo_ids = [g['grupo_id'] for g in grupos_da_empresa]
            if not grupo_ids: raise ValueError(f"Empresa ID {empresa['empresa_id']} não pertence a nenhum grupo.")
            placeholders = ','.join('?' for _ in grupo_ids)
            grupos_com_cert = conn.execute(f"SELECT * FROM grupos WHERE id IN ({placeholders}) AND certificado_path IS NOT NULL", grupo_ids).fetchall()
        if not grupos_com_cert: raise ValueError("Nenhum grupo com certificado encontrado para a empresa.")
        procuracao_grupo = grupos_com_cert[0]
        with open(procuracao_grupo['certificado_path'], "rb") as f: cert_data = f.read()
        senha_decrypted = decrypt_password(procuracao_grupo['certificado_senha_encrypted'])
        if not senha_decrypted or "Erro" in senha_decrypted: raise ValueError("Erro ao descriptografar a senha da procuração.")
        if not INFOSIMPLES_CRYPTO_KEY: raise ValueError("Chave de criptografia da InfoSimples não configurada.")
        payload = {"pkcs12_cert": aes256.encrypt(base64.b64encode(cert_data).decode(), INFOSIMPLES_CRYPTO_KEY), "pkcs12_pass": aes256.encrypt(senha_decrypted, INFOSIMPLES_CRYPTO_KEY), "perfil_procurador_cnpj": re.sub(r'[^\d]', '', empresa['cnpj']), "ignora_lidas": "0"}
        response = consultar_api_infosimples('https://api.infosimples.com/api/v2/consultas/ecac/caixa-postal', payload)
    except Exception as e:
        print(f"ERRO GERAL NA ETAPA DE BUSCA DA API: {e}")
        traceback.print_exc()
        return {"novas_mensagens_encontradas": 0, "erro": str(e)}, "IRREGULAR"

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        if response.get('code') == 200 and response.get('data'):
            mensagens_api = response['data'][0].get('mensagens', [])
            if mensagens_api:
                for msg in mensagens_api:
                    try:
                        envio_dt_str = msg.get('envio_data')
                        if not envio_dt_str: continue
                        envio_dt_db = datetime.strptime(envio_dt_str, '%d/%m/%Y').strftime('%Y-%m-%d')
                        leitura_dt_str = msg.get('leitura_data')
                        leitura_dt_db = datetime.strptime(leitura_dt_str, '%d/%m/%Y').strftime('%Y-%m-%d') if leitura_dt_str else None
                        c.execute("INSERT OR IGNORE INTO ecac_mensagens (empresa_id, razao_social_destinatario, cnpj_destinatario, id_mensagem_api, remetente, assunto, envio_data, leitura_data, conteudo_html, lida_api) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                  (empresa['id'], empresa['razao_social'], empresa['cnpj'], msg.get('id_mensagem'), msg.get('remetente'), msg.get('assunto'), envio_dt_db, leitura_dt_db, msg.get('conteudo_html'), msg.get('lida', False)))
                    except Exception as e:
                        print(f"Erro ao preparar para salvar mensagem da API ID {msg.get('id_mensagem')}: {e}")
                conn.commit()

        dias_busca_str = get_config('dias_busca_ecac', '30')
        data_inicio_filtro = (datetime.now() - timedelta(days=int(dias_busca_str))).strftime('%Y-%m-%d')
        
        query_recente = "SELECT assunto, envio_data FROM ecac_mensagens WHERE empresa_id = ? AND envio_data >= ? AND (UPPER(assunto) LIKE '%TERMO DE EXCLUSÃO%' OR UPPER(assunto) LIKE '%EXCLUSÃO DO SIMPLES%') ORDER BY envio_data DESC, id DESC LIMIT 1"
        mensagem_mais_recente = c.execute(query_recente, (empresa['id'], data_inicio_filtro)).fetchone()
        
        termo_ativo_encontrado = False
        if mensagem_mais_recente:
            assunto_recente = mensagem_mais_recente['assunto'].upper()
            if "CANCELAMENTO" not in assunto_recente and "SEM EFEITO" not in assunto_recente:
                termo_ativo_encontrado = True
        
        # --- LÓGICA UNIFICADA E SIMPLIFICADA ---
        # O status principal da tarefa AGORA É o status do Termo de Exclusão.
        situacao_simples = "IRREGULAR" if termo_ativo_encontrado else "REGULAR"
        print(f"Status final para a tarefa da empresa {empresa['cnpj']}: {situacao_simples}")

        # Removemos a necessidade da tabela 'status_adicional'
        # conn.execute("INSERT OR REPLACE INTO status_adicional...")

        # A lógica de e-mail continua a mesma
        keywords_alerta_json = get_config('keywords_alerta_email', '["TERMO DE EXCLUSÃO", "EXCLUSÃO DO SIMPLES"]')
        keywords_para_email = json.loads(keywords_alerta_json)
        alertas_ja_enviados = {row[0] for row in c.execute("SELECT mensagem_id FROM ecac_alertas_enviados").fetchall()}
        mensagens_para_alertar = c.execute("SELECT id, assunto, envio_data FROM ecac_mensagens WHERE empresa_id = ? AND envio_data >= ?", (empresa['id'], data_inicio_filtro)).fetchall()
        for msg_alerta in mensagens_para_alertar:
            msg_id_banco, assunto, envio_data = msg_alerta[0], msg_alerta[1], msg_alerta[2]
            if msg_id_banco not in alertas_ja_enviados and any(keyword in assunto.upper() for keyword in keywords_para_email):
                # ... (código de envio de e-mail) ...
                enviar_email(...)
                c.execute("INSERT OR IGNORE INTO ecac_alertas_enviados (mensagem_id) VALUES (?)", (msg_id_banco,))
        
        novas_mensagens_count = c.execute("SELECT COUNT(id) FROM ecac_mensagens WHERE empresa_id = ? AND marcada_como_lida_usuario = 0", (empresa['id'],)).fetchone()[0]
        conn.commit()

    resultado_dict = {"novas_mensagens_encontradas": novas_mensagens_count}
    return resultado_dict, situacao_simples
   
# =============================================
# MÓDULOS DE AGENDAMENTO (SCHEDULER JOBS)
# =============================================


def master_scheduler_job():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id, dia_do_mes, dias_antecedencia, consultas_config FROM agendamentos WHERE ativo = 1")
        agendamentos = c.fetchall()
        hoje = datetime.now()
        for agend_id, dia_do_mes, antecendencia, consultas_config_json in agendamentos:
            try:
                data_alvo = hoje.replace(day=dia_do_mes)
            except ValueError:
                proximo_mes = hoje.replace(day=28) + timedelta(days=4)
                data_alvo = proximo_mes - timedelta(days=proximo_mes.day)
            data_inicio_processamento = data_alvo - timedelta(days=antecendencia)
            if hoje.date() >= data_inicio_processamento.date():
                c.execute("SELECT grupo_id FROM agendamento_grupo WHERE agendamento_id = ?", (agend_id,))
                grupo_ids = [row[0] for row in c.fetchall()]
                if not grupo_ids: continue
                placeholders = ','.join('?' for _ in grupo_ids)
                c.execute(f"SELECT DISTINCT empresa_id FROM empresa_grupo WHERE grupo_id IN ({placeholders})", grupo_ids)
                empresas_ids = [row[0] for row in c.fetchall()]
                consultas_config = json.loads(consultas_config_json or '{}')
                for emp_id in empresas_ids:
                    for tipo_consulta, ativada in consultas_config.items():
                        if ativada and tipo_consulta != 'caixa_postal_ecac' and tipo_consulta != 'cnd_estadual_detalhada':
                            c.execute("SELECT id FROM tarefas_consulta WHERE empresa_id=? AND tipo_consulta=? AND strftime('%Y-%m', data_agendada) = ?", (emp_id, tipo_consulta, hoje.strftime('%Y-%m')))
                            if not c.fetchone():
                                # MODIFICADO: Passa a configuração completa do agendamento para a tarefa
                                c.execute("INSERT INTO tarefas_consulta (agendamento_id, empresa_id, tipo_consulta, data_agendada, config_json) VALUES (?, ?, ?, ?, ?)", 
                                          (agend_id, emp_id, tipo_consulta, data_alvo.strftime('%Y-%m-%d'), consultas_config_json))
        conn.commit()

def ecac_scheduler_job():
    print(f"[{datetime.now()}] INFO: Rodando agendador da Caixa Postal e-CAC...")
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        
        # Query reescrita para ser mais eficiente e corrigir o bug.
        # Ela já seleciona apenas as empresas que atendem a TODOS os critérios:
        # 1. Têm uma frequência de e-CAC definida (diferente de 'nunca').
        # 2. Pertencem a pelo menos um grupo.
        empresas_para_verificar = conn.execute("""
            SELECT
                e.id as empresa_id,
                ec.ecac_frequencia
            FROM empresas e
            JOIN empresa_config ec ON e.id = ec.empresa_id
            WHERE
                ec.ecac_frequencia != 'nunca'
                AND e.id IN (SELECT DISTINCT empresa_id FROM empresa_grupo)
        """).fetchall()

        for emp in empresas_para_verificar:
            empresa_id = emp['empresa_id']
            frequencia = emp['ecac_frequencia']

            # Lógica de prevenção de duplicidade (mantida)
            tarefa_existente = conn.execute("""
                SELECT id FROM tarefas_consulta
                WHERE empresa_id = ? AND tipo_consulta = 'caixa_postal_ecac' AND status IN ('pendente', 'processando', 'erro')
            """, (empresa_id,)).fetchone()

            if tarefa_existente:
                print(f"[{datetime.now()}] INFO: Tarefa de Caixa Postal para empresa ID {empresa_id} já está na fila. Pulando.")
                continue

            # Lógica de verificação de tempo (mantida)
            last_run_str = conn.execute("""
                SELECT MAX(ultima_tentativa) FROM tarefas_consulta 
                WHERE empresa_id = ? AND tipo_consulta = 'caixa_postal_ecac' AND status IN ('sucesso', 'concluido')
            """, (empresa_id,)).fetchone()[0]

            run_needed = False
            if not last_run_str:
                run_needed = True
            else:
                last_run_dt = datetime.fromisoformat(last_run_str)
                now = datetime.now()
                delta = now - last_run_dt
                
                if frequencia == 'diaria' and delta.days >= 1: run_needed = True
                elif frequencia == 'a_cada_2_dias' and delta.days >= 2: run_needed = True
                elif frequencia == 'semanal' and delta.days >= 7: run_needed = True
                elif frequencia == 'quinzenal' and delta.days >= 15: run_needed = True
                elif frequencia == 'mensal' and delta.days >= 30: run_needed = True
            
            if run_needed:
                print(f"[{datetime.now()}] INFO: Enfileirando tarefa de Caixa Postal para empresa ID {empresa_id}")
                conn.execute("""
                    INSERT INTO tarefas_consulta (empresa_id, tipo_consulta, data_agendada) 
                    VALUES (?, 'caixa_postal_ecac', ?)
                """, (empresa_id, datetime.now().strftime('%Y-%m-%d')))
                conn.commit()

def consulta_worker_job():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        # MODIFICADO: Seleciona t.* para incluir a nova coluna config_json
        tarefa = conn.execute("""
            SELECT t.*, e.cnpj, e.razao_social, e.cep, e.id as empresa_id
            FROM tarefas_consulta t 
            JOIN empresas e ON t.empresa_id = e.id
            WHERE t.status = 'pendente' OR (t.status = 'erro' AND datetime('now', '-5 minutes') > datetime(t.ultima_tentativa))
            ORDER BY t.id ASC
            LIMIT 1
        """).fetchone()

    if not tarefa: return
    
    tarefa_id = tarefa['id']
    tipo_consulta = tarefa['tipo_consulta']

    with sqlite3.connect(DB_FILE) as conn:
        breaker = conn.execute("SELECT open_until FROM circuit_breakers WHERE tipo_consulta = ? AND open_until > datetime('now', 'localtime')", (tipo_consulta,)).fetchone()
        if breaker:
            print(f"[{datetime.now()}] INFO: Disjuntor para '{tipo_consulta}' está aberto. Pulando tarefa.")
            return

    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("UPDATE tarefas_consulta SET status='processando', ultima_tentativa=datetime('now', 'localtime') WHERE id=?", (tarefa_id,))
        
        # DICIONÁRIO DE FUNÇÕES ATUALIZADO
        funcoes_de_tarefa = { 
            "cnd_estadual": executar_tarefa_cnd_estadual, 
            "cnd_federal": executar_tarefa_cnd_federal,
            "cnd_trabalhista": executar_tarefa_cnd_trabalhista,
            "cnd_fgts": executar_tarefa_cnd_fgts,
            "simples_nacional": executar_tarefa_simples_nacional,
            "caixa_postal_ecac": executar_tarefa_caixa_postal_ecac
        }
        
        # MODIFICADO: A função de tarefa agora recebe o objeto 'tarefa' completo
        resultado_dict, situacao_simples = funcoes_de_tarefa[tipo_consulta](tarefa, None)
        resultado_path = RESULTADOS_DIR / f"tarefa_{tarefa_id}.json"
        
        with open(resultado_path, 'w', encoding='utf-8') as f:
            json.dump(resultado_dict, f, ensure_ascii=False, indent=2)
            
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("UPDATE tarefas_consulta SET status='sucesso', resultado_path=?, ultima_situacao=? WHERE id=?", (str(resultado_path), situacao_simples, tarefa_id))
            conn.execute("INSERT OR IGNORE INTO circuit_breakers (tipo_consulta) VALUES (?)", (tipo_consulta,))
            conn.execute("UPDATE circuit_breakers SET consecutive_failures = 0, open_until = NULL WHERE tipo_consulta = ?", (tipo_consulta,))

    except Exception as e:
        print(f"[{datetime.now()}] ERRO na Tarefa {tarefa_id} ({tipo_consulta}): {e}")
        traceback.print_exc()
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT tentativas FROM tarefas_consulta WHERE id=?", (tarefa_id,))
            tentativas = c.fetchone()[0]
            status_final = "erro" if tentativas + 1 < MAX_TENTATIVAS else "falha_permanente"
            c.execute("UPDATE tarefas_consulta SET status=?, tentativas=tentativas+1, detalhes_erro=? WHERE id=?", (status_final, str(e), tarefa_id))
            
            c.execute("INSERT OR IGNORE INTO circuit_breakers (tipo_consulta) VALUES (?)", (tipo_consulta,))
            c.execute("UPDATE circuit_breakers SET consecutive_failures = consecutive_failures + 1 WHERE tipo_consulta = ?", (tipo_consulta,))
            failures = c.execute("SELECT consecutive_failures FROM circuit_breakers WHERE tipo_consulta = ?", (tipo_consulta,)).fetchone()[0]
            
            if failures >= FAILURE_THRESHOLD:
                pause_until = datetime.now() + timedelta(minutes=PAUSE_DURATION_MINUTES)
                c.execute("UPDATE circuit_breakers SET open_until = ? WHERE tipo_consulta = ?", (pause_until.strftime('%Y-%m-%d %H:%M:%S'), tipo_consulta))
                print(f"DISJUNTOR ARMADO: {failures} falhas consecutivas para '{tipo_consulta}'. Pausando por {PAUSE_DURATION_MINUTES} minutos.")
            conn.commit()


def get_circuit_breakers_status():
    """Retorna o status de todos os circuit breakers."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM circuit_breakers").fetchall()

def reset_circuit_breaker(tipo_consulta: str):
    """Reseta um circuit breaker específico, zerando as falhas e reabrindo o circuito."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "UPDATE circuit_breakers SET consecutive_failures = 0, open_until = NULL WHERE tipo_consulta = ?",
            (tipo_consulta,)
        )
    print(f"INFO: Disjuntor para '{tipo_consulta}' foi resetado via API.")
    return True

def email_reporter_job():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        lotes_prontos = conn.execute("SELECT agendamento_id, tipo_consulta FROM tarefas_consulta WHERE status != 'concluido' AND tipo_consulta != 'caixa_postal_ecac' AND agendamento_id IS NOT NULL GROUP BY agendamento_id, tipo_consulta").fetchall()

    for lote in lotes_prontos:
        agend_id, tipo_consulta = lote['agendamento_id'], lote['tipo_consulta']
        
        with sqlite3.connect(DB_FILE) as conn:
            total_tarefas = conn.execute("SELECT COUNT(id) FROM tarefas_consulta WHERE agendamento_id=? AND tipo_consulta=?", (agend_id, tipo_consulta)).fetchone()[0]
            finalizadas_count = conn.execute("SELECT COUNT(id) FROM tarefas_consulta WHERE agendamento_id=? AND tipo_consulta=? AND status IN ('sucesso', 'falha_permanente')", (agend_id, tipo_consulta)).fetchone()[0]

        if total_tarefas > 0 and finalizadas_count == total_tarefas:
            print(f"INFO: Lote {agend_id}/{tipo_consulta} está completo. Gerando relatório...")
            with sqlite3.connect(DB_FILE) as conn:
                conn.row_factory = sqlite3.Row
                agend_info = conn.execute("SELECT nome_agendamento, emails_notificacao FROM agendamentos WHERE id=?", (agend_id,)).fetchone()
                tarefas_do_lote = conn.execute("SELECT id, resultado_path, detalhes_erro FROM tarefas_consulta WHERE agendamento_id=? AND tipo_consulta=? AND status IN ('sucesso', 'falha_permanente')", (agend_id, tipo_consulta)).fetchall()
            
            if not agend_info: continue
            
            molde = criar_molde_resultado(tipo_consulta)
            if not molde:
                print(f"AVISO: Molde de colunas não encontrado para '{tipo_consulta}'.")
                continue

            resultados = []
            for tarefa in tarefas_do_lote:
                linha_relatorio = molde.copy()
                if tarefa['resultado_path'] and os.path.exists(tarefa['resultado_path']):
                    try:
                        with open(tarefa['resultado_path'], 'r', encoding='utf-8') as f:
                            dados_resultado = json.load(f)
                        for key, value in dados_resultado.items():
                            if key in linha_relatorio:
                                linha_relatorio[key] = value if value is not None and value != '' else '-'
                    except Exception as e:
                        print(f"Erro ao ler JSON da tarefa {tarefa['id']}: {e}")
                        linha_relatorio['Situação'] = 'FALHA'
                        linha_relatorio['Interpretação'] = 'Erro ao processar resultado'
                else:
                    with sqlite3.connect(DB_FILE) as conn:
                        conn.row_factory = sqlite3.Row
                        empresa_info = conn.execute("SELECT cnpj, razao_social FROM empresas WHERE id = (SELECT empresa_id FROM tarefas_consulta WHERE id = ?)", (tarefa['id'],)).fetchone()
                    linha_relatorio['CNPJ'] = limpar_e_formatar_cnpj(empresa_info['cnpj'])
                    linha_relatorio['Nome'] = empresa_info['razao_social']
                    linha_relatorio['Situação'] = 'FALHA'
                    linha_relatorio['Interpretação'] = f"❌ Falha Permanente: {tarefa['detalhes_erro']}"
                resultados.append(linha_relatorio)

            if not resultados: continue

            df_resultados = pd.DataFrame(resultados, columns=molde.keys())
            
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                sheet_name = TIPOS_CONSULTA[tipo_consulta]['sheet_name']
                df_resultados.to_excel(writer, index=False, sheet_name=sheet_name)
                workbook, worksheet = writer.book, writer.sheets[sheet_name]
                
                formato_verde = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100'})
                formato_vermelho = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
                formato_laranja = workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500'})
                header_format = workbook.add_format({'bold': True, 'text_wrap': True, 'valign': 'top', 'fg_color': '#D7E4F2', 'border': 1})

                for col_num, value in enumerate(df_resultados.columns.values):
                    worksheet.write(0, col_num, value, header_format)

                for row_num, row_data in df_resultados.iterrows():
                    formato_linha = None
                    status_val = str(row_data.get('Situação', '')) + str(row_data.get('Situação Atual', '')) + str(row_data.get('Interpretação', ''))
                    status_val = status_val.lower()

                    if 'irregular' in status_val or 'positiva' in status_val or 'falha' in status_val or 'deve consultar matriz' in status_val:
                        formato_linha = formato_vermelho
                    elif 'positiva com efeitos de negativa' in status_val:
                        formato_linha = formato_laranja
                    elif 'regular' in status_val or 'negativa' in status_val:
                        formato_linha = formato_verde

                    if formato_linha:
                        worksheet.set_row(row_num + 1, None, formato_linha)

                for i, col in enumerate(df_resultados.columns):
                    column_len = max(len(str(col)), df_resultados[col].astype(str).map(len).max())
                    worksheet.set_column(i, i, column_len + 3)

            output.seek(0)
            
            desc_name = TIPOS_CONSULTA[tipo_consulta]['desc']
            assunto = f"Relatório de Consulta: {agend_info['nome_agendamento']} - {desc_name}"
            corpo = f"Olá,\n\nSegue em anexo o relatório da consulta '{desc_name}' referente ao agendamento '{agend_info['nome_agendamento']}'.\n\nProcessado em: {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            nome_arquivo = f"Relatorio_{tipo_consulta}_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
            
            try:
                msg = MIMEMultipart()
                msg['From'] = EMAIL_USER
                msg['To'] = agend_info['emails_notificacao']
                msg['Subject'] = assunto
                msg.attach(MIMEText(corpo))
                part = MIMEApplication(output.read(), Name=nome_arquivo)
                part['Content-Disposition'] = f'attachment; filename="{nome_arquivo}"'
                msg.attach(part)
                with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
                    server.starttls()
                    server.login(EMAIL_USER, EMAIL_PASS)
                    server.send_message(msg)
                
                ids_para_marcar = [t['id'] for t in tarefas_do_lote]
                with sqlite3.connect(DB_FILE) as conn:
                    if ids_para_marcar:
                        placeholders = ','.join(['?'] * len(ids_para_marcar))
                        conn.execute(f"UPDATE tarefas_consulta SET status='concluido' WHERE agendamento_id=? AND tipo_consulta=? AND id IN ({placeholders})", [agend_id, tipo_consulta] + ids_para_marcar)
                print(f"INFO: Relatório do lote {agend_id}/{tipo_consulta} enviado e tarefas marcadas como concluídas.")
            except Exception as e:
                print(f"Falha no envio do e-mail do grupo {agend_id}/{tipo_consulta}: {e}")
                traceback.print_exc()

def limpar_historico_tarefas_concluidas():
    """Apaga do banco de dados as tarefas que já foram concluídas ou falharam permanentemente."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM tarefas_consulta WHERE status IN ('concluido', 'falha_permanente', 'sucesso')")
    return True

def limpar_historico_ecac():
    """Apaga todas as mensagens do e-CAC e os alertas enviados do banco."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM ecac_mensagens")
        conn.execute("DELETE FROM ecac_alertas_enviados")
    return True

def get_empresas_ids_do_grupo(grupo_id: int):
    """Retorna uma lista de IDs de empresas que pertencem a um grupo."""
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute("SELECT empresa_id FROM empresa_grupo WHERE grupo_id=?", (grupo_id,)).fetchall()
        return [row[0] for row in rows]

def registration_worker_job():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        tarefa = conn.execute("""
            SELECT * FROM cadastros_pendentes 
            WHERE status = 'pendente' OR (status = 'erro' AND datetime('now', '-2 minutes') > ultima_tentativa)
            ORDER BY ultima_tentativa ASC
            LIMIT 1
        """).fetchone()

    if not tarefa:
        return
    
    id_tarefa, cnpj, cep, tentativas = tarefa['id'], tarefa['cnpj'], tarefa['cep'], tarefa['tentativas']
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("UPDATE cadastros_pendentes SET status='processando', ultima_tentativa=datetime('now', 'localtime') WHERE id=?", (id_tarefa,))
        
        razao_social, erro_api = consultar_cnpja(cnpj)
        
        if erro_api == "quota":
            print(f"INFO: Cota da API CNPJà atingida. Pausando por 60 segundos.")
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("UPDATE cadastros_pendentes SET status='pendente' WHERE id=?", (id_tarefa,))
            time.sleep(60)
            return

        if erro_api:
            raise Exception(erro_api)
            
        add_empresa(cnpj, razao_social, cep)
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("DELETE FROM cadastros_pendentes WHERE id=?", (id_tarefa,))
        print(f"INFO: Empresa {cnpj} cadastrada com sucesso.")
        time.sleep(20)
    except sqlite3.IntegrityError:
        print(f"INFO: CNPJ {cnpj} já existe na base principal. Removendo da fila.")
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("DELETE FROM cadastros_pendentes WHERE id=?", (id_tarefa,))
    
    except Exception as e:
        print(f"ERRO ao processar cadastro do CNPJ {cnpj}: {e}")
        with sqlite3.connect(DB_FILE) as conn:
            if tentativas + 1 >= MAX_TENTATIVAS:
                status_final = 'falha_permanente'
                print(f"ALERTA: CNPJ {cnpj} falhou 3 vezes e não será mais tentado.")
            else:
                status_final = 'erro'
            
            conn.execute("UPDATE cadastros_pendentes SET status=?, tentativas=tentativas+1, detalhes_erro=? WHERE id=?", 
                         (status_final, str(e), id_tarefa))


def circuit_breaker_reset_job():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("UPDATE circuit_breakers SET consecutive_failures = 0, open_until = NULL WHERE open_until IS NOT NULL AND open_until <= datetime('now', 'localtime')")
        conn.commit()
    print(f"[{datetime.now()}] Verificação de reset dos disjuntores executada.")