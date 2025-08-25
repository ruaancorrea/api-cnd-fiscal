# models.py (versão final e completa)
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import date, datetime

# --- Base Models ---
class EmpresaBase(BaseModel):
    cnpj: str
    razao_social: str
    cep: Optional[str] = None

class GrupoBase(BaseModel):
    nome: str

class AgendamentoBase(BaseModel):
    nome_agendamento: str
    emails_notificacao: str
    consultas_config: Dict[str, bool]
    grupo_ids: List[int]
    dia_do_mes: int = Field(..., ge=1, le=28)

class DocumentoBase(BaseModel):
    tipo_documento: str
    descricao: Optional[str] = None
    data_vencimento: date

# --- Response Models ---
class Empresa(EmpresaBase):
    id: int
    criado_em: str
    ecac_frequencia: Optional[str] = 'nunca'
    class Config:
        from_attributes = True

class Grupo(GrupoBase):
    id: int
    certificado_vencimento: Optional[date] = None
    total_empresas: int
    class Config:
        from_attributes = True

class Agendamento(AgendamentoBase):
    id: int
    ativo: bool
    class Config:
        from_attributes = True

class Documento(DocumentoBase):
    id: int
    empresa_id: int
    arquivo_path: str
    class Config:
        from_attributes = True

class MensagemEcac(BaseModel):
    id: int
    empresa_id: int
    razao_social_destinatario: Optional[str] = None
    assunto: Optional[str] = None
    envio_data: Optional[date] = None
    marcada_como_lida_usuario: bool
    conteudo_html: Optional[str] = None
    class Config:
        from_attributes = True
        
class Tarefa(BaseModel):
    ID: int
    Empresa: Optional[str] = None
    Consulta: str
    Status: str
    Resultado: Optional[str] = None
    Data_Alvo: Optional[str] = None
    Última_Tentativa: Optional[str] = None
    Tentativas: int
    Erro: Optional[str] = None
    class Config:
        from_attributes = True
        
class Dossie(BaseModel):
    info: Dict[str, Any]
    resultados: Dict[str, Optional[Dict[str, Any]]]

class StatusResponse(BaseModel):
    message: str

class ConsultaAvulsaRequest(BaseModel):
    empresa_ids: List[int]
    tipos_consulta: List[str]
    config_detalhada_estadual: Optional[bool] = False

class ConsultaAvulsaResponse(BaseModel):
    message: str
    tarefas_criadas: int
    job_id: str

class DashboardMetrics(BaseModel):
    total_empresas: int
    certificados_vencendo_60d: int
    pendencias_federal: int
    pendencias_estadual: int
    pendencias_trabalhista: int
    pendencias_fgts: int
    mensagens_ecac_nao_lidas: int

class GrupoEmpresasUpdate(BaseModel):
    empresa_ids: List[int]

class ConfiguracoesSistema(BaseModel):
    dias_busca_ecac: int
    keywords_alerta_email: List[str]