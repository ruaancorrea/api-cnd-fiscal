from fastapi import FastAPI, HTTPException, Body, Path, UploadFile, File, Form
from typing import List, Dict, Optional
import core_logic
import models
from fastapi import Query
import json
from datetime import date
import os


# Altere a inicialização do app para a versão simples:
app = FastAPI(
    title="API de Consultas Fiscais",
    description="Backend completo para o sistema de automação de consultas fiscais.",
    version="2.0.0"
    # A linha "lifespan=lifespan" foi removida
)



SETUP_KEY = os.getenv("SETUP_KEY", "trocar-essa-chave-secreta")

@app.post("/sistema/inicializar-banco", tags=["Sistema"], include_in_schema=False)
def inicializar_banco(key: str):
    """
    Endpoint protegido para inicializar o banco de dados pela primeira vez.
    'include_in_schema=False' o esconde da documentação pública.
    """
    if key != SETUP_KEY:
        raise HTTPException(status_code=403, detail="Chave de setup inválida.")

    try:
        print("Iniciando a criação da estrutura do banco de dados via API...")
        core_logic.init_db()
        return {"status": "Banco de dados inicializado com sucesso."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao inicializar o banco de dados: {str(e)}")

# --- TAG: Dashboard ---
@app.get("/dashboard/metrics", response_model=models.DashboardMetrics, tags=["Dashboard"])
def get_metrics():
    """Retorna os principais indicadores para a tela de dashboard."""
    return core_logic.get_dashboard_metrics()

# --- TAG: Empresas ---
@app.get("/empresas", response_model=List[models.Empresa], tags=["Empresas"])
def listar_empresas():
    return core_logic.get_empresas()

@app.post("/empresas", response_model=models.Empresa, status_code=201, tags=["Empresas"])
def criar_empresa(empresa: models.EmpresaBase):
    try:
        empresa_id = core_logic.add_empresa(empresa.cnpj, empresa.razao_social, empresa.cep)
        return core_logic.get_empresa_por_id(empresa_id)
    except core_logic.sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail=f"O CNPJ {empresa.cnpj} já está cadastrado.")

@app.post("/empresas/upload-massa", tags=["Empresas"])
async def upload_empresas_massa(file: UploadFile = File(...)):
    """Envia uma planilha (.xlsx ou .csv) para cadastrar empresas em massa."""
    if not (file.filename.endswith('.xlsx') or file.filename.endswith('.csv')):
        raise HTTPException(status_code=400, detail="Formato de arquivo inválido. Use .xlsx ou .csv.")
    
    file_content = await file.read()
    file_type = 'csv' if file.filename.endswith('.csv') else 'excel'
    adicionados, error = core_logic.add_empresas_from_file(file_content, file_type)
    if error:
        raise HTTPException(status_code=500, detail=f"Erro ao processar arquivo: {error}")
    return {"message": f"{adicionados} empresas adicionadas à fila de cadastro."}

@app.get("/empresas/{empresa_id}", response_model=models.Empresa, tags=["Empresas"])
def obter_empresa(empresa_id: int):
    empresa = core_logic.get_empresa_por_id(empresa_id)
    if not empresa:
        raise HTTPException(status_code=404, detail="Empresa não encontrada.")
    return empresa

@app.delete("/empresas/{empresa_id}", status_code=204, tags=["Empresas"])
def remover_empresa(empresa_id: int):
    core_logic.delete_empresa(empresa_id)
    return

@app.get("/empresas/{empresa_id}/dossie", response_model=models.Dossie, tags=["Empresas"])
def obter_dossie(empresa_id: int):
    dossie = core_logic.get_dossie_data(empresa_id)
    if not dossie or not dossie.get('info'):
        raise HTTPException(status_code=404, detail="Empresa não encontrada ou sem dados de dossiê.")
    return dossie

@app.put("/empresas/{empresa_id}/config/ecac", response_model=models.Empresa, tags=["Empresas"])
def configurar_frequencia_ecac(empresa_id: int, frequencia: str = Body(..., embed=True)):
    """Atualiza a frequência de verificação do e-CAC para uma empresa."""
    core_logic.update_empresa_ecac_config(empresa_id, frequencia)
    return core_logic.get_empresa_por_id(empresa_id)

# --- TAG: Documentos ---
@app.get("/empresas/{empresa_id}/documentos", response_model=List[models.Documento], tags=["Documentos"])
def listar_documentos_empresa(empresa_id: int):
    """Lista todos os documentos associados a uma empresa."""
    docs = core_logic.get_documentos_da_empresa(empresa_id)
    return [dict(doc) for doc in docs]

@app.post("/empresas/{empresa_id}/documentos", response_model=models.Documento, status_code=201, tags=["Documentos"])
async def adicionar_documento(empresa_id: int, file: UploadFile = File(...), tipo_documento: str = Form(...), data_vencimento: date = Form(...), descricao: Optional[str] = Form(None)):
    """Adiciona um novo documento a uma empresa, com upload de arquivo."""
    file_path = core_logic.DOCUMENTOS_DIR / f"emp_{empresa_id}_{file.filename}"
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())
    core_logic.add_documento(empresa_id, tipo_documento, descricao, data_vencimento.strftime('%Y-%m-%d'), str(file_path))
    # Retorna o último documento adicionado para confirmação (simplificado)
    new_doc = core_logic.get_documentos_da_empresa(empresa_id)[0]
    return dict(new_doc)

@app.delete("/documentos/{documento_id}", status_code=204, tags=["Documentos"])
def remover_documento(documento_id: int):
    """Deleta um documento pelo seu ID único."""
    core_logic.delete_documento(documento_id)
    return

# --- TAG: Grupos ---
@app.get("/grupos", response_model=List[models.Grupo], tags=["Grupos"])
def listar_grupos():
    return core_logic.get_grupos()

@app.post("/grupos", response_model=models.Grupo, status_code=201, tags=["Grupos"])
def criar_grupo(grupo: models.GrupoBase):
    try:
        core_logic.add_grupo(grupo.nome)
        # Retorna o último grupo adicionado (simplificado)
        return core_logic.get_grupos()[-1]
    except core_logic.sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Um grupo com este nome já existe.")

@app.delete("/grupos/{grupo_id}", status_code=204, tags=["Grupos"])
def remover_grupo(grupo_id: int):
    core_logic.delete_grupo(grupo_id)
    return

@app.put("/grupos/{grupo_id}/empresas", response_model=models.StatusResponse, tags=["Grupos"])
def atualizar_empresas_do_grupo(grupo_id: int, data: models.GrupoEmpresasUpdate):
    """Substitui a lista de empresas de um grupo pela lista fornecida."""
    core_logic.update_empresa_grupos(grupo_id, data.empresa_ids)
    return {"message": "Lista de empresas do grupo atualizada com sucesso."}

@app.post("/grupos/{grupo_id}/certificado", tags=["Grupos"])
async def upload_certificado_grupo(grupo_id: int, file: UploadFile = File(...), senha: str = Form(...)):
    """Faz o upload de um certificado .pfx e senha para um grupo."""
    if not file.filename.endswith('.pfx'):
        raise HTTPException(status_code=400, detail="Arquivo deve ser .pfx")
    
    pfx_data = await file.read()
    expiry_date = core_logic.get_certificate_expiry_date(pfx_data, senha)
    if not expiry_date:
        raise HTTPException(status_code=400, detail="Não foi possível ler o certificado. Verifique o arquivo e a senha.")

    cert_path = core_logic.CERTIFICADOS_DIR / f"grupo_{grupo_id}_{file.filename}"
    with open(cert_path, "wb") as f: f.write(pfx_data)
    
    encrypted_pass = core_logic.encrypt_password(senha)
    core_logic.update_grupo_certificado(grupo_id, str(cert_path), encrypted_pass, expiry_date.strftime('%Y-%m-%d'))
    return {"message": "Certificado salvo com sucesso.", "vencimento": expiry_date.strftime('%d/%m/%Y')}

# --- TAG: Agendamentos ---
@app.get("/agendamentos", response_model=List[models.Agendamento], tags=["Agendamentos"])
def listar_agendamentos():
    agends = core_logic.get_agendamentos()
    # Converte o campo de config para dict
    results = []
    for agend in agends:
        agend_dict = dict(agend)
        agend_dict['consultas_config'] = json.loads(agend_dict['consultas_config'])
        # Placeholder para grupo_ids, que precisaria de mais uma query
        agend_dict['grupo_ids'] = [g['grupo_id'] for g in core_logic.get_grupos_do_agendamento(agend_dict['id'])]
        results.append(agend_dict)
    return results

@app.post("/agendamentos", response_model=models.Agendamento, status_code=201, tags=["Agendamentos"])
def criar_agendamento(agendamento: models.AgendamentoBase):
    agendamento_id = core_logic.create_agendamento(agendamento.dict())
    agend_data, grupo_ids = core_logic.get_agendamento_por_id(agendamento_id)
    agend_data['grupo_ids'] = grupo_ids
    return agend_data

@app.put("/agendamentos/{agendamento_id}", response_model=models.Agendamento, tags=["Agendamentos"])
def editar_agendamento(agendamento_id: int, agendamento: models.AgendamentoBase):
    core_logic.update_agendamento(agendamento_id, agendamento.nome_agendamento, agendamento.emails_notificacao, agendamento.dia_do_mes, agendamento.consultas_config, agendamento.grupo_ids)
    agend_data, grupo_ids = core_logic.get_agendamento_por_id(agendamento_id)
    agend_data['grupo_ids'] = grupo_ids
    return agend_data

@app.delete("/agendamentos/{agendamento_id}", status_code=204, tags=["Agendamentos"])
def remover_agendamento(agendamento_id: int):
    core_logic.delete_agendamento(agendamento_id)
    return

# --- TAG: Consultas ---
@app.post("/consultas/executar", response_model=models.ConsultaAvulsaResponse, tags=["Consultas"])
def executar_consulta_avulsa(request: models.ConsultaAvulsaRequest):
    if not request.empresa_ids or not request.tipos_consulta:
        raise HTTPException(status_code=400, detail="É necessário fornecer IDs de empresas e tipos de consulta.")
    config = {'cnd_estadual_detalhada': request.config_detalhada_estadual}
    tarefas_criadas, job_id = core_logic.criar_tarefas_avulsas(request.empresa_ids, request.tipos_consulta, config)
    if tarefas_criadas == 0:
        raise HTTPException(status_code=404, detail="Nenhuma tarefa foi criada. Verifique se os IDs das empresas existem.")
    return {"message": "Tarefas de consulta enfileiradas com sucesso.", "tarefas_criadas": tarefas_criadas, "job_id": job_id}

# --- TAG: Tarefas e e-CAC (já existentes) ---
@app.get("/tarefas", response_model=List[models.Tarefa], tags=["Tarefas"])
def listar_tarefas():
    with core_logic.sqlite3.connect(core_logic.DB_FILE) as conn:
        conn.row_factory = core_logic.sqlite3.Row
        query = "SELECT t.id as 'ID', e.razao_social as 'Empresa', t.tipo_consulta as 'Consulta', t.status as 'Status', t.ultima_situacao as 'Resultado', t.data_agendada as 'Data_Alvo', t.ultima_tentativa as 'Última_Tentativa', t.tentativas as 'Tentativas', t.detalhes_erro as 'Erro' FROM tarefas_consulta t JOIN empresas e ON t.empresa_id = e.id ORDER BY t.id DESC LIMIT 500"
        tarefas = conn.execute(query).fetchall()
        return [dict(row) for row in tarefas]

@app.get("/ecac/mensagens-nao-lidas", response_model=List[models.MensagemEcac], tags=["e-CAC"])
def listar_mensagens_nao_lidas(empresa_id: Optional[int] = None):
    rows = core_logic.get_caixa_postal_nao_lidas(empresa_id)
    return [dict(row) for row in rows]
    
@app.post("/ecac/mensagens/{mensagem_id}/marcar-lida", response_model=models.StatusResponse, tags=["e-CAC"])
def marcar_como_lida(mensagem_id: int):
    core_logic.marcar_mensagem_como_lida(mensagem_id)
    return {"message": f"Mensagem {mensagem_id} marcada como lida com sucesso."}

# --- TAG: Configurações ---
@app.get("/configuracoes", response_model=models.ConfiguracoesSistema, tags=["Configurações"])
def get_configuracoes():
    """Lê as configurações atuais do sistema."""
    dias = core_logic.get_config('dias_busca_ecac', '30')
    keywords_json = core_logic.get_config('keywords_alerta_email', '["TERMO DE EXCLUSÃO", "EXCLUSÃO DO SIMPLES"]')
    return {
        "dias_busca_ecac": int(dias),
        "keywords_alerta_email": json.loads(keywords_json)
    }

@app.put("/configuracoes", response_model=models.ConfiguracoesSistema, tags=["Configurações"])
def set_configuracoes(config: models.ConfiguracoesSistema):
    """Atualiza as configurações do sistema."""
    core_logic.set_config('dias_busca_ecac', str(config.dias_busca_ecac))
    core_logic.set_config('keywords_alerta_email', json.dumps(config.keywords_alerta_email))
    return config


# --- TAG: Sistema ---
@app.get("/sistema/circuit-breakers", tags=["Sistema"])
def listar_circuit_breakers():
    """Retorna o status de todos os disjuntores de consulta (Circuit Breakers)."""
    breakers = core_logic.get_circuit_breakers_status()
    return [dict(b) for b in breakers]

@app.post("/sistema/circuit-breakers/reset", response_model=models.StatusResponse, tags=["Sistema"])
def resetar_circuit_breaker(tipo_consulta: str = Body(..., embed=True)):
    """Força o reset de um disjuntor de consulta que esteja aberto."""
    core_logic.reset_circuit_breaker(tipo_consulta)
    return {"message": f"Disjuntor para '{tipo_consulta}' foi resetado com sucesso."}

# Adicione também este endpoint na TAG "Documentos"
@app.get("/documentos/vencendo", tags=["Documentos"])
def listar_documentos_vencendo():
    """Retorna uma lista de documentos e licenças vencendo nos próximos 60 dias."""
    documentos = core_logic.get_documentos_vencendo()
    return [dict(d) for d in documentos]

# Adicione este endpoint na TAG "Grupos"
@app.get("/grupos/{grupo_id}/empresas", response_model=List[int], tags=["Grupos"])
def listar_ids_empresas_do_grupo(grupo_id: int):
    """Retorna uma lista contendo apenas os IDs das empresas que pertencem ao grupo."""
    return core_logic.get_empresas_ids_do_grupo(grupo_id)

# Adicione este endpoint na TAG "Agendamentos"
@app.post("/agendamentos/{agendamento_id}/toggle-active", response_model=models.Agendamento, tags=["Agendamentos"])
def alternar_status_agendamento(agendamento_id: int):
    """Ativa ou desativa um agendamento."""
    agend_data, _ = core_logic.get_agendamento_por_id(agendamento_id)
    if not agend_data:
        raise HTTPException(status_code=404, detail="Agendamento não encontrado.")
    
    novo_status = 0 if agend_data['ativo'] else 1
    core_logic.toggle_agendamento_ativo(agendamento_id, novo_status)
    
    agend_data_atualizado, grupo_ids = core_logic.get_agendamento_por_id(agendamento_id)
    agend_data_atualizado['grupo_ids'] = grupo_ids
    return agend_data_atualizado

# Adicione este endpoint na TAG "Tarefas"
@app.delete("/tarefas/historico", response_model=models.StatusResponse, tags=["Tarefas"])
def limpar_historico_tarefas():
    """Limpa o histórico de tarefas já processadas (status 'sucesso', 'concluido', 'falha_permanente')."""
    core_logic.limpar_historico_tarefas_concluidas()
    return {"message": "Histórico de tarefas concluídas foi limpo com sucesso."}

# Adicione este endpoint na TAG "e-CAC"
@app.delete("/ecac/mensagens/historico", response_model=models.StatusResponse, tags=["e-CAC"])
def limpar_mensagens_ecac():
    """Limpa o histórico de todas as mensagens do e-CAC do banco de dados."""
    core_logic.limpar_historico_ecac()
    return {"message": "Histórico de mensagens do e-CAC foi limpo com sucesso."}



@app.get("/sistema/verificar-banco", tags=["Sistema"])
def verificar_banco():
    """Verifica se a tabela principal do banco de dados existe."""
    try:
        with core_logic.sqlite3.connect(core_logic.DB_FILE) as conn:
            conn.execute("SELECT id FROM empresas LIMIT 1")
        return {"status": "SUCESSO", "message": "O banco de dados está inicializado e a tabela 'empresas' existe."}
    except Exception as e:
        return {"status": "FALHA", "message": f"O banco de dados parece não estar inicializado. Erro: {str(e)}"}