import logging
import threading

import customtkinter as ctk
import psutil  # <- IMPORTANTE! Faltava isso no original
from sqlalchemy import text

# Importe suas telas separadas (ajuste o caminho de acordo com seu projeto)
from application import (  # Exemplo
    ConfigData,
    DashboardFrame,
    Kill,
    MonitorFrame,
    NetworkCore,
    SettingsFrame,
    thread_proxy,
)
from configs import (
    app_config,
    azul_hexadecimal,
    ctk_button_labels,
    general_settings,
    graphs_configs,
    gray,
    green_hexadecimal,
    vermelho_hexadecimal,
)
from database import ConfigSessionLocal, Configuration, TrafficLog, TrafficSessionLocal

logger = logging.getLogger(__name__)


class App(ctk.CTk):
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.running = True
        self.after_id = None

        self.kill_manager = Kill()
        self.dashboard_frame = DashboardFrame(master=self, controller=self)
        self.monitor_frame = MonitorFrame(master=self, controller=self)
        self.settings_frame = SettingsFrame(master=self, controller=self)
        self.config_data = ConfigData(master=self.settings_frame, controller=self)
        self.config_data.pack(side="bottom", fill="both", expand=True, pady=10)

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.title(app_config.get("app_name"))
        self.geometry(app_config.get("window_size", "1000x600"))
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.setup_sidebar()
        self.select_frame_by_name("dashboard")
        self.update_loop()

    def setup_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(
            self.sidebar_frame,
            text=app_config.get("logo_name"),
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(pady=30)

        self.btn_dash = ctk.CTkButton(
            self.sidebar_frame,
            text=ctk_button_labels.get("dashboard"),
            height=40,
            command=lambda: self.select_frame_by_name("dashboard"),
        )

        self.btn_dash.pack(pady=10, padx=20)

        self.btn_monitor = ctk.CTkButton(
            self.sidebar_frame,
            text=ctk_button_labels.get("monitor"),
            height=40,
            command=lambda: self.select_frame_by_name("monitor"),
        )

        self.btn_monitor.pack(pady=10, padx=20)

        self.btn_kill = ctk.CTkButton(
            self.sidebar_frame,
            text=ctk_button_labels.get("kill"),
            fg_color=vermelho_hexadecimal,
            hover_color="#7b241c",
            command=self.kill_manager.kill_browsers,
        )

        self.btn_kill.pack(side="bottom", pady=30, padx=20)

        self.settings = ctk.CTkButton(
            self.sidebar_frame,
            text=ctk_button_labels.get("settings"),
            height=40,
            command=lambda: self.select_frame_by_name("settings"),
        )
        self.settings.pack(pady=10, padx=20)

    def select_frame_by_name(self, name):
        # Esconde todos os frames
        self.dashboard_frame.grid_forget()
        self.monitor_frame.grid_forget()
        self.settings_frame.grid_forget()
        self.config_data.grid_forget()  #

        # Reseta cores
        self.btn_dash.configure(fg_color=gray)
        self.btn_monitor.configure(fg_color=gray)
        self.settings.configure(fg_color=gray)

        # Mostra o selecionado
        if name == "dashboard":
            self.btn_dash.configure(fg_color=azul_hexadecimal)
            self.dashboard_frame.grid(row=0, column=1, sticky="nsew")

        elif name == "monitor":
            self.btn_monitor.configure(fg_color=azul_hexadecimal)
            self.monitor_frame.grid(row=0, column=1, sticky="nsew")

        elif name == "settings":
            self.settings.configure(fg_color=azul_hexadecimal)
            self.settings_frame.grid(row=0, column=1, sticky="nsew")

    def update_loop(self):
        if not self.running:
            return

        db_config = ConfigSessionLocal()
        db_traffic = TrafficSessionLocal()

        try:
            config = db_config.query(Configuration).filter_by(id=1234).first()

            qtd_visivel = (
                config.traffic_visible
                if config
                else general_settings.get("amount_of_visible_traffic", 100)
            )

            # 1. ATUALIZA A TABELA NO MONITOR FRAME
            logs = (
                db_traffic.query(TrafficLog).order_by(TrafficLog.id.desc()).limit(qtd_visivel).all()
            )

            # Limpa a tabela usando a referência do monitor_frame
            self.monitor_frame.tree.delete(*self.monitor_frame.tree.get_children())

            for log in logs:
                self.monitor_frame.tree.insert(
                    "",
                    "end",
                    values=(
                        log.id,
                        log.timestamp.strftime("%H:%M:%S"),
                        log.method,
                        log.host,
                        log.size,
                    ),
                )

            # 2. ATUALIZA OS GRÁFICOS APENAS SE A TELA ESTIVER ATIVA
            if self.dashboard_frame.winfo_ismapped():
                df = self.dashboard_frame
                pie_conf = graphs_configs.get("pie")
                barh_conf = graphs_configs.get("barh")
                line_conf = graphs_configs.get("line")

                # Host Bar Chart

                df.ax_host.clear()
                res_h = db_traffic.execute(text(barh_conf.get("query"))).fetchall()
                if res_h:
                    df.ax_host.barh(
                        [r[0][:20] for r in res_h], [r[1] for r in res_h], color=azul_hexadecimal
                    )
                df.ax_host.set_title(
                    barh_conf.get("title"),
                    fontsize=barh_conf.get("font_size"),
                    color=barh_conf.get("text_color"),
                )

                # Method Pie Chart
                df.ax_meth.clear()
                res_m = db_traffic.execute(text(pie_conf.get("query"))).fetchall()
                if res_m:
                    df.ax_meth.pie(
                        [r[1] for r in res_m],
                        labels=[r[0] for r in res_m],
                        autopct="%1.1f%%",
                        textprops={"color": pie_conf.get("text_color")},
                    )
                df.ax_meth.set_title(
                    pie_conf.get("title"),
                    fontsize=pie_conf.get("font_size"),
                    color=pie_conf.get("text_color"),
                )

                # RAM Line Chart
                df.ax_ram.clear()
                mem = psutil.virtual_memory().percent
                self.core.ram_history.append(mem)

                if len(self.core.ram_history) > 30:
                    self.core.ram_history.pop(0)
                df.ax_ram.plot(self.core.ram_history, color=green_hexadecimal, linewidth=2)
                df.ax_ram.set_title(
                    f"{line_conf.get('title')} {mem}%",
                    fontsize=line_conf.get("font_size"),
                    color=line_conf.get("text_color"),
                )

                df.ax_ram.set_yticks([0, 25, 50, 75, 100])
                df.fig.tight_layout()
                df.canvas.draw()

        except Exception as e:
            logger.error(f"Erro no loop de atualização: {e}")

        finally:
            db_config.close()
            db_traffic.close()

        if self.core.running:
            self.after_id = self.after(2000, self.update_loop)

    def on_close(self):
        """Fecha aplicação corretamente"""

        logger.info("Encerrando interface...")

        # Mostrar tela indicando encerramento
        closing_win = ctk.CTkToplevel(self)
        closing_win.title("Encerrando...")
        closing_win.geometry("300x150")
        closing_win.attributes("-topmost", True)

        # Centralizar na tela (aproximado)

        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - 150
        y = self.winfo_y() + (self.winfo_height() // 2) - 75
        closing_win.geometry(f"+{x}+{y}")

        ctk.CTkLabel(
            closing_win,
            text="Encerrando Proxy e App...\nPor favor aguarde.",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(expand=True)

        self.update()

        def do_close():
            try:
                self.core.shutdown()

                if self.after_id:
                    self.after_cancel(self.after_id)

            except Exception as e:
                logger.error(f"Erro ao fechar app: {e}")
            finally:
                self.destroy()

                import os

                os._exit(0)

        self.after(1000, do_close)


if __name__ == "__main__":
    core = NetworkCore()

    threading.Thread(target=thread_proxy, args=(core,), daemon=True).start()

    App(core).mainloop()
