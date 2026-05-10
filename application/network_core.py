from .traffic_engine import TrafficFilterEngine
from mitmproxy import http
from database import (
    ConfigSessionLocal,
    TrafficSessionLocal,
    TrafficLog,
    Configuration,
    WhiteList,
    BlackList,
)
import logging

logger = logging.getLogger(__name__)


class NetworkCore:
    """
    Auxiliar para gerenciamento de janelas e informações
    """

    def __init__(self):
        self.running = True
        self.ram_history = []
        self.stats = {"total": 0, "alerts": 0}
        self.filter_engine = TrafficFilterEngine()

        # cache em memória
        self.whitelist = set()
        self.blacklist = set()

        self.load_configs()

    # =========================
    # LOAD INICIAL (CACHE)
    # =========================
    def load_configs(self):
        db = ConfigSessionLocal()

        try:
            # Config global (id fixo)
            config = db.query(Configuration).filter_by(id=1234).first()

            if config:
                self.theme = config.theme
                self.traffic_visible = config.traffic_visible
            else:
                self.theme = None
                self.traffic_visible = None

            # WhiteList
            white = db.query(WhiteList).all()
            self.whitelist = {
                item.url.url for item in white if item.url
            }

            # BlackList
            black = db.query(BlackList).all()
            self.blacklist = {
                item.url.url for item in black if item.url
            }

        except Exception as e:
            logger.error(f"Erro ao carregar configs: {e}")

        finally:
            db.close()

    # =========================
    # PROCESS REQUEST
    # =========================
    def process_flow(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host

        # Engine principal
        self.filter_engine.handle_request(flow)

        # Se já houve resposta (bloqueio/modificação)
        if flow.response:
            self.stats["alerts"] += 1
            return

        # WhiteList (persistente)
        if host in self.whitelist:
            return

        db = TrafficSessionLocal()

        try:
            content = flow.request.content or b""
            payload = content.decode(errors="ignore")[:1000]

            log = TrafficLog(
                host=host,
                method=flow.request.method,
                size=len(content),
                headers=str(flow.request.headers),
                payload=payload,
            )

            db.add(log)
            db.commit()

            self.stats["total"] += 1

        except Exception as e:
            db.rollback()
            logger.error(f"Erro ao salvar log: {e}")

        finally:
            db.close()

        # Blacklist (persistente)
        if host in self.blacklist:
            flow.kill()

    # =========================
    # PROCESS RESPONSE
    # =========================
    def process_response(self, flow: http.HTTPFlow):
        self.filter_engine.handle_response(flow)

    # =========================
    # RELOAD CONFIG (opcional)
    # =========================
    def reload(self):
        """
        Recarrega configs do banco (use quando alterar via UI/API)
        """
        self.load_configs()


    def shutdown(self):

        logger.info("Encerrando NetworkCore...")

        self.running = False

        try:

            if hasattr(self, "proxy_master"):
                if hasattr(self, "loop"):
                    self.loop.call_soon_threadsafe(self.proxy_master.shutdown)
                else:
                    self.proxy_master.shutdown()

        except Exception as e:

            logger.error(
                f"Erro ao encerrar proxy: {e}"
            )