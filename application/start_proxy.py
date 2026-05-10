import asyncio
from .sentinela import SentinelAddon
from database import ExcludeHeader, ConfigSessionLocal
from sqlalchemy import select
from mitmproxy.options import Options
from configs import listen_host, listen_port
from mitmproxy.tools.dump import DumpMaster
import logging
import os

logger = logging.getLogger(__name__)


async def start_proxy(core):
    """Inicia a proxy"""

    # =========================
    # LOAD HEADERS
    # =========================
    with ConfigSessionLocal() as session:

        resultados = session.scalars(
            select(ExcludeHeader)
        ).all()

        headers_to_pop = [
            item.field_name
            for item in resultados
        ]

    # =========================
    # CONFIG MITMPROXY
    # =========================
    opts = Options(
        listen_host=listen_host,
        listen_port=listen_port,
        mode=["regular"]
    )

    master = DumpMaster(opts)

    # salva referência global
    core.proxy_master = master

    # =========================
    # LOAD SCRIPTS
    # =========================
    content = ""

    try:

        script_paths = [
            "scripts/localization_injection.js",
            "scripts/banner.js"
        ]

        scripts = []

        for path in script_paths:

            if not os.path.exists(path):
                logger.warning(f"Script não encontrado: {path}")
                continue

            with open(path, encoding="utf-8") as f:
                scripts.append(f.read())

        content = "\n\n".join(scripts)

    except Exception:

        logger.exception(
            "Erro ao carregar scripts JS"
        )

    # =========================
    # ADDON
    # =========================
    master.addons.add(
        SentinelAddon(
            content=content,
            headers_to_pop=headers_to_pop,
            core=core
        )
    )

    # =========================
    # RUN
    # =========================
    try:

        logger.info(
            f"Proxy iniciado em "
            f"{listen_host}:{listen_port}"
        )

        await master.run()

    except asyncio.CancelledError:

        logger.info("Proxy cancelado")

    except Exception as e:

        logger.exception(
            f"Erro no proxy: {e}"
        )

    finally:

        logger.info("Encerrando DumpMaster...")

        try:
            master.shutdown()
        except Exception:
            pass

        logger.info("Proxy encerrado com sucesso")