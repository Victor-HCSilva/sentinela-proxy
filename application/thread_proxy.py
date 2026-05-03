import asyncio
import subprocess
from configs import general_settings
import logging
import os
from .start_proxy import start_proxy

logger = logging.getLogger(__name__)


def thread_proxy(core):
    """Encerrar programa com comando 'kill'"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if os.name != 'nt': # Comando fuser é geralmente para sistemas Unix-like
        try:
            subprocess.run(general_settings.get("kill_proxy_command"), stderr=subprocess.DEVNULL, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Erro ao encerrar proxy com fuser: {e}")
        except Exception as e:
            logger.error(f"Erro inesperado ao encerrar proxy: {e}")

    loop.run_until_complete(start_proxy(core))
