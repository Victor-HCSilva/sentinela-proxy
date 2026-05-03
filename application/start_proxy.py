from .sentinela import SentinelAddon
from database import ExcludeHeader, SessionLocal
from sqlalchemy import select
from mitmproxy.options import Options
from configs import listen_host, listen_port
from mitmproxy.tools.dump import DumpMaster
import logging


logger = logging.getLogger(__name__)


async def start_proxy(core):
    """Inicia a proxy"""
    stmt = select(ExcludeHeader)
    
    with SessionLocal() as session:
        stmt = select(ExcludeHeader)
        resultados = session.scalars(stmt).all()
        headers_to_pop = [item.field_name for item in resultados]
    opts = Options(listen_host=listen_host, listen_port=listen_port, mode=["regular"])
    master = DumpMaster(opts)

    try:
        with open(
            file="scripts/localization_injection.js",
            encoding="utf-8", mode="r"
        ) as script:
            content = script.read()
    except Exception as e:
        logger.info(f"Erro ao ler script JS: {e}")
        content = ""

    master.addons.add(SentinelAddon(content=content, headers_to_pop=headers_to_pop, core=core))
    await master.run()
