from .traffic_engine import TrafficFilterEngine
from mitmproxy import http
from database import SessionLocal,   TrafficLog
import logging 
from configs import general_settings

logging = logging.getLogger()

class NetworkCore:
    """
    Definição de proxy
    """
    def __init__(self):
        self.blacklist = set()
        self.ram_history = []
        self.stats = {"total": 0, "alerts": 0}
        self.filter_engine = TrafficFilterEngine()


    def process_flow(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        self.filter_engine.handle_request(flow)

        if flow.response:
            self.stats["alerts"] += 1
            return

        host = flow.request.pretty_host

        if host in general_settings.get("white_list"): 
            return

        db = SessionLocal()
        
        try:
            payload = flow.request.content.decode(errors='ignore')[:1000] if flow.request.content else ""
            log = TrafficLog(
                host=host, method=flow.request.method,
                size=len(flow.request.content) if flow.request.content else 0,
                headers=str(flow.request.headers), payload=payload
            )
            db.add(log)
            db.commit()
            self.stats["total"] += 1
        except Exception as e:
            # TODO: Salvar em arquivo de log, talvez outra tabela apenas para erros do sistema
            logging.info(f"Erro ao salvar log: {e}")
        finally:
            db.close()

        if host in self.blacklist:
            flow.kill()

    def process_response(self, flow: http.HTTPFlow):
        self.filter_engine.handle_response(flow)

