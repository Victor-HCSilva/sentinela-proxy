import logging
from tkinter import messagebox

import psutil

from configs.settings import general_settings, kill_command_message

logger = logging.getLogger(__name__)


class Kill:
    """
    Classe que lida com o encerramento de navegadores.
    Usa o psutil para isso (import psutil)
    """

    def kill_browsers(self) -> None:
        f"""
        Encerra os navegadores ativos
        lista de navegadores:
        {general_settings.get("programs_name")}
        """
        targets = general_settings.get("programs_name")
        count = 0

        for proc in psutil.process_iter(["name"]):
            if any(t in proc.info["name"].lower() for t in targets):
                try:
                    proc.kill()
                    count += 1
                except psutil.NoSuchProcess:
                    logger.warning(
                        f"Processo {proc.info['name']} não encontrado ao tentar encerrar."
                    )
                except psutil.AccessDenied:
                    logger.error(
                        f"Acesso negado ao tentar encerrar processo {proc.info['name']}. Executar como administrador pode ser necessário."
                    )

        messagebox.showinfo(
            kill_command_message.get("content_title"),
            f"{kill_command_message.get('message')} {count} processos finalizados.",
        )
