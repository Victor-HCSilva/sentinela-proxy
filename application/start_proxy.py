import asyncio
import logging
import os

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from sqlalchemy import select

from configs import listen_host, listen_port
from database import ConfigSessionLocal, ExcludeHeader

from .sentinela import SentinelAddon

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)


async def start_proxy(core):
    """Inicia a proxy"""

    # =========================
    # LOAD HEADERS
    # =========================
    with ConfigSessionLocal() as session:
        resultados = session.scalars(select(ExcludeHeader)).all()

        headers_to_pop = [item.field_name for item in resultados]

    # =========================
    # CONFIG MITMPROXY
    # =========================
    opts = Options(listen_host=listen_host, listen_port=listen_port, mode=["regular"])

    master = DumpMaster(opts)

    # salva referência global
    core.proxy_master = master

    # =========================
    # LOAD SCRIPTS
    # =========================
    content = ""

    try:
        default_path = "scripts"
        script_paths = [
            f"{default_path}/localizationInjection.js",
            f"{default_path}/popup/banner.js",
            f"{default_path}/ui.js",
            f"{default_path}/extract.js",
            f"{default_path}/ollama.js",
            f"{default_path}/content.js",
        ]

        scripts = []

        for path in script_paths:
            if not os.path.exists(path):
                logger.warning(f"⚠️ Script não encontrado: {path}")
                continue

            with open(path, encoding="utf-8") as f:
                scripts.append(f.read())
                logger.info(f"🟢 Arquivo {path} lido")

        content = "\n\n".join(scripts)

    except Exception:
        logger.exception("🔴 Erro ao carregar scripts JS")

    # =========================
    # ADDON
    # =========================
    master.addons.add(
        SentinelAddon(content=content, headers_to_pop=headers_to_pop, core=core)
    )

    # =========================
    # RUN
    # =========================
    try:
        logger.info(f"Proxy iniciado em {listen_host}:{listen_port}")

        await master.run()

    except asyncio.CancelledError:
        logger.info("Proxy cancelado")

    except Exception as e:
        logger.exception(f"Erro no proxy: {e}")

    finally:
        logger.info("Encerrando DumpMaster...")

        try:
            master.shutdown()
        except Exception:
            pass

        logger.info("Proxy encerrado com sucesso")
