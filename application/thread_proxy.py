import asyncio
import subprocess
from configs import general_settings
import logging
import os
from .start_proxy import start_proxy

logger = logging.getLogger(__name__)


def thread_proxy(core):

    loop = asyncio.new_event_loop()

    asyncio.set_event_loop(loop)

    core.loop = loop

    if os.name != "nt":

        try:

            subprocess.run(
                general_settings.get("kill_proxy_command"),
                stderr=subprocess.DEVNULL,
                check=True
            )

        except subprocess.CalledProcessError as e:
            logger.info(f"Nenhum proxy anterior encontrado. Erro: {e}")

        except Exception as e:
            logger.error(f"Erro inesperado ao encerrar proxy: {e}")

    try:

        loop.run_until_complete(
            start_proxy(core)
        )

    except Exception as e:

        logger.error(f"Erro no proxy: {e}")

    finally:

        pending = asyncio.all_tasks(loop)

        for task in pending:
            task.cancel()

        try:
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        except Exception as e:
            logger.info(f"Erro na thread: {e}")

    loop.stop()
    loop.close()

    logger.info("Loop asyncio encerrado")