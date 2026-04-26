import logging
import customtkinter as ctk
from tkinter import ttk, messagebox
import threading
import asyncio
import os
import subprocess
import psutil

# Gráficos e Dados
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sqlalchemy import text

# mitmproxy
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# Importações de seus módulos locais
from application import NetworkCore # Assumindo que você tem este módulo
from database import SessionLocal, TrafficLog # Assumindo que você tem este módulo

# Importações de configurações (certifique-se de que o arquivo configs.py está no mesmo diretório ou no PYTHONPATH)
from configs import (
    general_settings,
    app_config,
    ctk_button_labels,
    table,
    inspector_window,
    kill_command_message,
    graphs_configs,
    listen_host,
    listen_port,
    auth_labels,
    auth_window,
    # Importe as cores definidas para uso consistente
    azul_hexadecimal,
    vermelho_hexadecimal, # Adicionei aqui, caso 'red_hexadecimal' seja usado em outro lugar
    green_hexadecimal,
    gray,
)

# Configuração do logger (com nome)
logger = logging.getLogger(__name__)

# Configurações Visuais do CustomTkinter
ctk.set_appearance_mode(general_settings.get("theme"))
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    """
    App com tkinter estilo dark para visual mais agradável
    Visa monitorar conexões http/https e encerrar conexões
    suspeitas
    """
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.title(app_config.get("app_name"))
        self.geometry(app_config.get("window_size"))

        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.setup_sidebar()
        self.setup_main_frames()

        self.select_frame_by_name("dashboard")
        self.update_loop()

    def setup_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, text=app_config.get("logo_name"),
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.logo_label.pack(pady=30)

        self.btn_dash = ctk.CTkButton(
            self.sidebar_frame, text=ctk_button_labels.get("dashboard"),
            height=40, command=lambda: self.select_frame_by_name("dashboard")
        )
        self.btn_dash.pack(pady=10, padx=20)

        self.btn_monitor = ctk.CTkButton(
            self.sidebar_frame, text=ctk_button_labels.get("monitor"),
            height=40, command=lambda: self.select_frame_by_name("monitor"))

        self.btn_monitor.pack(pady=10, padx=20)

        self.btn_kill = ctk.CTkButton(
            self.sidebar_frame,
            text=ctk_button_labels.get("kill"),
            fg_color=vermelho_hexadecimal, # Usando a variável de cor
            hover_color="#7b241c", # Mantive o hover_color hardcoded, mas poderia ser outra variável
            command=self.kill_browsers
        )
        self.btn_kill.pack(side="bottom", pady=30, padx=20)

    def setup_main_frames(self):
        self.dash_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        self.fig, (self.ax_host, self.ax_meth, self.ax_ram) = plt.subplots(3, 1, figsize=(6, 12))
        self.fig.patch.set_facecolor('#1a1a1a')
        for ax in [self.ax_host, self.ax_meth, self.ax_ram]:
            ax.set_facecolor('#1a1a1a')
            ax.tick_params(colors='white')
            ax.title.set_color('white')

        self.canvas = FigureCanvasTkAgg(
            self.fig, master=self.dash_frame
        )
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)

        # FRAME MONITOR
        self.monitor_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        ctk.CTkLabel(
            self.monitor_frame, text="Histórico de Conexões (Duplo clique para inspecionar)",
            font=ctk.CTkFont(size=15)).pack(pady=10
        )

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0, font=('Arial', 10))
        style.configure("Treeview.Heading", background="#333333", foreground="white", relief="flat")
        style.map("Treeview", background=[('selected', azul_hexadecimal)]) # Usando a variável de cor

        self.tree = ttk.Treeview(
            self.monitor_frame,
            columns=list(table.keys()), # CORREÇÃO: Usar as chaves do dicionário 'table'
            show='headings'
        )

        # Loop para configurar cabeçalhos e colunas
        for column_id, column_data in table.items():
            heading_text = column_data["heading"]["text"]
            column_config = column_data["column"]

            self.tree.heading(column_id, text=heading_text)
            self.tree.column(column_id, **column_config)

        self.tree.pack(fill="both", expand=True, padx=20, pady=10)
        self.tree.bind("<Double-1>", self.open_inspection)

    def select_frame_by_name(self, name):
        if name == "dashboard":
            self.btn_dash.configure(fg_color=azul_hexadecimal) # CORREÇÃO: Usando a variável
            self.btn_monitor.configure(fg_color=gray) # CORREÇÃO: Usando a variável
            self.dash_frame.grid(row=0, column=1, sticky="nsew")
            self.monitor_frame.grid_forget()
        else: # name == "monitor"
            self.btn_dash.configure(fg_color=gray) # CORREÇÃO: Usando a variável
            self.btn_monitor.configure(fg_color=azul_hexadecimal) # CORREÇÃO: Usando a variável
            self.monitor_frame.grid(row=0, column=1, sticky="nsew")
            self.dash_frame.grid_forget()

    def open_inspection(self, event):
        item = self.tree.selection()
        if not item:
            return
        log_id = self.tree.item(item[0])['values'][0]

        db = SessionLocal()
        log = db.query(TrafficLog).filter(TrafficLog.id == log_id).first()
        db.close()

        if log:
            box = inspector_window.get("box")

            win = ctk.CTkToplevel(self)
            win.title(f"{inspector_window.get("inspector_title")}: {log.host}")
            win.geometry(inspector_window.get("inspector_detail_size"))
            win.attributes("-topmost", True)

            txt = ctk.CTkTextbox(
                win,
                **box
            )
            txt.pack(padx=10, pady=10)

            # NOTE: Aqui a visualização dos dados em detalhe
            data = f"DOMÍNIO: {log.host}\nMÉTODO: {log.method}\nTAMANHO: {log.size} bytes\n"
            data += f"\n--- HEADERS ---\n{log.headers}\n"
            data += f"\n--- PAYLOAD (BODY) ---\n{log.payload if log.payload else '[Vazio]'}"
            txt.insert("0.0", data)

    def kill_browsers(self):
        targets = general_settings.get("programs_name")
        count = 0

        for proc in psutil.process_iter(['name']):
            if any(t in proc.info['name'].lower() for t in targets):
                try:
                    proc.kill()
                    count += 1
                except psutil.NoSuchProcess:
                    logger.warning(f"Processo {proc.info['name']} não encontrado ao tentar encerrar.")
                except psutil.AccessDenied:
                    logger.error(f"Acesso negado ao tentar encerrar processo {proc.info['name']}. Executar como administrador pode ser necessário.")


        messagebox.showinfo(
            kill_command_message.get("content_title"),
            f"{kill_command_message.get("message")} {count} processos finalizados."
        )

    def update_loop(self):
        quantidade_de_trafegos_visiveis = general_settings.get("amount_of_visible_traffic")
        db = SessionLocal()
        try:
            pie_conf = graphs_configs.get("pie")
            barh_conf = graphs_configs.get("barh")
            line_conf = graphs_configs.get("line")

            logs = db.query(TrafficLog).order_by(TrafficLog.id.desc()).limit(quantidade_de_trafegos_visiveis).all()
            self.tree.delete(*self.tree.get_children())

            for log in logs:
                self.tree.insert("", "end", values=(log.id, log.timestamp.strftime("%H:%M:%S"), log.method, log.host, log.size))

            if self.dash_frame.winfo_ismapped():

                # Host Bar (Horizontal)
                self.ax_host.clear()
                res_h = db.execute(text(barh_conf.get("query"))).fetchall()
                if res_h:
                    self.ax_host.barh([r[0][:20] for r in res_h], [r[1] for r in res_h], color=azul_hexadecimal) # Usando a variável
                self.ax_host.set_title(barh_conf.get("title"), fontsize=barh_conf.get("font_size"), color=barh_conf.get("text_color"))

                # Pizza
                self.ax_meth.clear()
                res_m = db.execute(text(pie_conf.get("query"))).fetchall()

                if res_m:
                    self.ax_meth.pie([r[1] for r in res_m], labels=[r[0] for r in res_m], autopct='%1.1f%%', textprops={'color':pie_conf.get("text_color")}) # Usando a variável de cor
                self.ax_meth.set_title(pie_conf.get("title"), fontsize=pie_conf.get("font_size"), color=pie_conf.get("text_color"))

                # RAM Line
                self.ax_ram.clear()
                mem = psutil.virtual_memory().percent
                self.core.ram_history.append(mem)

                if len(self.core.ram_history) > 30:
                    self.core.ram_history.pop(0)

                self.ax_ram.plot(self.core.ram_history, color=green_hexadecimal, linewidth=2) # Usando a variável
                self.ax_ram.set_title(f"{line_conf.get("title")} {mem}%", fontsize=line_conf.get("font_size"), color=line_conf.get("text_color"))
                self.ax_ram.set_ylim(0, 100)

                self.fig.tight_layout()
                self.canvas.draw()

        except Exception as e:
            logger.error(f"Erro no loop de atualização: {e}") # Usando logger
            # os.system("Erro no loop de atualização de gráficos") # Remover, pois o logger já registra
        finally:
            db.close()

        self.after(2000, self.update_loop)


async def start_proxy(core):
    # TODO: arquivo .env ou de configuração
    opts = Options(listen_host=listen_host, listen_port=listen_port, mode=["regular"])
    master = DumpMaster(opts)

    class SentinelAddon:
        def request(self, flow):
            core.process_flow(flow)

        def response(self, flow):
            core.process_response(flow)

    master.addons.add(SentinelAddon())
    await master.run()

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
    else: # Para Windows, talvez um comando diferente ou psutil
        logger.info("Comando 'fuser' não disponível no Windows. O proxy pode não ser encerrado automaticamente.")
        # Você pode adicionar lógica aqui para Windows se precisar encerrar portas

    loop.run_until_complete(start_proxy(core))


if __name__ == "__main__":
    login = ctk.CTk()
    login.title(auth_window.get("auth_title")) # CORREÇÃO: Acessando "auth_title"
    login.geometry(auth_window.get("window_size"))

    def auth():
        if ent.get() == "admin": # TODO: Implementar autenticação segura
            login.destroy()
            core = NetworkCore()
            threading.Thread(target=thread_proxy, args=(core,), daemon=True).start()
            App(core).mainloop()
        else:
            msg_config = auth_labels.get("incorret_password_message")
            messagebox.showerror(
                title=msg_config.get("context_title"),
                message=msg_config.get("message")
            )

    ctk.CTkLabel(login, text=auth_labels.get("content_title"), font=auth_labels.get("font")).pack(pady=20)
    ent = ctk.CTkEntry(login, placeholder_text=auth_labels.get("placeholder_text"), show="*")
    ent.pack(pady=10)
    ctk.CTkButton(login, text=ctk_button_labels.get("login"), command=auth).pack(pady=10)
    login.mainloop()