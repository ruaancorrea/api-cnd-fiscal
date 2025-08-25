# worker.py
import time
from apscheduler.schedulers.background import BackgroundScheduler
import core_logic

print("Iniciando o Worker em Background...")

# Inicializa o banco de dados para o worker ter acesso
core_logic.init_db()
core_logic.atualizar_banc_de_dados()

# Configura e inicia o scheduler
scheduler = BackgroundScheduler(daemon=True, timezone='America/Sao_Paulo')
scheduler.add_job(core_logic.master_scheduler_job, 'interval', minutes=1, id='master_scheduler')
scheduler.add_job(core_logic.ecac_scheduler_job, 'interval', minutes=1, id='ecac_scheduler')
scheduler.add_job(core_logic.consulta_worker_job, 'interval', seconds=45, id='consulta_worker')
scheduler.add_job(core_logic.email_reporter_job, 'interval', minutes=5, id='email_reporter')
scheduler.add_job(core_logic.registration_worker_job, 'interval', seconds=10, id='registration_worker')
scheduler.add_job(core_logic.circuit_breaker_reset_job, 'interval', minutes=10, id='circuit_breaker_reset_job')
scheduler.start()

print("Scheduler iniciado com todos os jobs. O Worker está rodando.")

# Mantém o script rodando para sempre
try:
    while True:
        time.sleep(60)
except (KeyboardInterrupt, SystemExit):
    scheduler.shutdown()