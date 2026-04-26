import logging
import customtkinter as ctk
from tkinter import ttk, messagebox
import threading
import asyncio
import os
import subprocess
import psutil
import tempfile
from datetime import datetime


# Gráficos e Dados
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text as SQLText, text
from sqlalchemy.orm import sessionmaker, declarative_base

# mitmproxy
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

logger = logging.getLogger()

# Configurações Visuais
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# NOTE: Está sendo salvo em /tmp  
# Engine de banco de dados
Base = declarative_base()
db_path = os.path.join(tempfile.gettempdir(), "sentinela_v6_fixed.db")
engine = create_engine(f'sqlite:///{db_path}', connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(bind=engine)

# TODO: Coloca em arquivo separado ou mudar estratégia de guardar informações 
class TrafficLog(Base):
    __tablename__ = 'traffic_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now)
    host = Column(String)
    method = Column(String)
    size = Column(Integer)
    headers = Column(SQLText)
    payload = Column(SQLText)

Base.metadata.create_all(bind=engine)


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

        if host in ["127.0.0.1", "localhost"]: 
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


class App(ctk.CTk):
    """
    App com tkinter esilo dark para visual mais agradável
    Visa monitorar conexões http/https e encerrar conexões 
    suspeitas
    """
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.title("SENTINELA NETWORK GUARDIAN Pro")
        self.geometry("1100x850")

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
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="SENTINELA", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.pack(pady=30)

        self.btn_dash = ctk.CTkButton(self.sidebar_frame, text="Dashboard", 
                                     height=40, command=lambda: self.select_frame_by_name("dashboard"))
        self.btn_dash.pack(pady=10, padx=20)

        self.btn_monitor = ctk.CTkButton(self.sidebar_frame, text="Monitor Real-Time", 
                                        height=40, command=lambda: self.select_frame_by_name("monitor"))
        self.btn_monitor.pack(pady=10, padx=20)

        self.btn_kill = ctk.CTkButton(self.sidebar_frame, text="FIREWALL KILL", fg_color="#922b21", 
                                     hover_color="#7b241c", command=self.kill_browsers)
        self.btn_kill.pack(side="bottom", pady=30, padx=20)

    def setup_main_frames(self):
        # FRAME DASHBOARD
        self.dash_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        
        self.fig, (self.ax_host, self.ax_meth, self.ax_ram) = plt.subplots(3, 1, figsize=(6, 12))
        self.fig.patch.set_facecolor('#1a1a1a')
        for ax in [self.ax_host, self.ax_meth, self.ax_ram]:
            ax.set_facecolor('#1a1a1a')
            ax.tick_params(colors='white')
            ax.title.set_color('white')

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.dash_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)

        # FRAME MONITOR
        self.monitor_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        
        ctk.CTkLabel(self.monitor_frame, text="Histórico de Conexões (Duplo clique para inspecionar)", 
                     font=ctk.CTkFont(size=15)).pack(pady=10)

        # TODO: colors (talvez constants)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0, font=('Arial', 10))
        style.configure("Treeview.Heading", background="#333333", foreground="white", relief="flat")
        style.map("Treeview", background=[('selected', '#1f538d')])

        self.tree = ttk.Treeview(self.monitor_frame, columns=("ID", "HORA", "MÉD", "HOST", "SIZE"), show='headings')
        self.tree.heading("ID", text="ID")
        self.tree.column("ID", width=50)
        self.tree.heading("HORA", text="HORA")
        self.tree.column("HORA", width=80)
        self.tree.heading("MÉD", text="MÉD")
        self.tree.column("MÉD", width=60)
        self.tree.heading("HOST", text="DOMÍNIO/URL")
        self.tree.column("HOST", width=450)
        self.tree.heading("SIZE", text="BYTES")
        self.tree.column("SIZE", width=80)
        
        self.tree.pack(fill="both", expand=True, padx=20, pady=10)
        self.tree.bind("<Double-1>", self.open_inspection)# NOTE: Doule click aqui

    def select_frame_by_name(self, name):
        # Correção do Erro de Cor: Usando apenas strings fixas para evitar o ValueError de tupla transparente
        if name == "dashboard":
            self.btn_dash.configure(fg_color="#1f538d")
            self.btn_monitor.configure(fg_color="gray25")
            self.dash_frame.grid(row=0, column=1, sticky="nsew")
            self.monitor_frame.grid_forget()
        else:
            self.btn_dash.configure(fg_color="gray25")
            self.btn_monitor.configure(fg_color="#1f538d") # TODO: colors.py
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
            win = ctk.CTkToplevel(self)
            win.title(f"Packet Inspector: {log.host}")
            win.geometry("700x500") # TODO: constants.py 
            win.attributes("-topmost", True)
            
            txt = ctk.CTkTextbox(win, width=680, height=480, font=("Consolas", 12))
            txt.pack(padx=10, pady=10)
            
            # NOTE: Aqui a visualização dos dados em detalhe
            data = f"DOMÍNIO: {log.host}\nMÉTODO: {log.method}\nTAMANHO: {log.size} bytes\n"
            data += f"\n--- HEADERS ---\n{log.headers}\n"
            data += f"\n--- PAYLOAD (BODY) ---\n{log.payload if log.payload else '[Vazio]'}"
            txt.insert("0.0", data)

    def kill_browsers(self):
        # TODO: Arquivo de configuração com nomes dos processos
        targets = ["chrome", "firefox", "msedge", "brave"]
        count = 0

        for proc in psutil.process_iter(['name']):
            if any(t in proc.info['name'].lower() for t in targets):
                proc.kill()
                count += 1
            
        messagebox.showinfo("Firewall Active", f"Protocolo de encerramento concluído. {count} processos finalizados.")

    def update_loop(self):
        quantidade_de_trafegos_visiveis = 32
        db = SessionLocal()
        try:
            # Atualizar Tabela
            # NOTE: Aqui está algo mais decente com ORM
            logs = db.query(TrafficLog).order_by(TrafficLog.id.desc()).limit(quantidade_de_trafegos_visiveis).all()
            self.tree.delete(*self.tree.get_children())
            for log in logs:
                self.tree.insert("", "end", values=(log.id, log.timestamp.strftime("%H:%M:%S"), log.method, log.host, log.size))

            # TODO: SQL puro sendo usado
            # Atualizar Gráficos (Somente se a aba Dashboard estiver visível para poupar CPU)
            if self.dash_frame.winfo_ismapped():
                # Host Bar (Horizontal)
                self.ax_host.clear()
                res_h = db.execute(text("SELECT host, COUNT(id) as c FROM traffic_logs GROUP BY host ORDER BY c DESC LIMIT 5")).fetchall()
                if res_h: 
                    self.ax_host.barh([r[0][:20] for r in res_h], [r[1] for r in res_h], color='#1f538d')
                self.ax_host.set_title("TOP 5 DESTINOS", fontsize=10, color="white") 

                # Pizza
                self.ax_meth.clear()
                res_m = db.execute(text("SELECT method, COUNT(id) FROM traffic_logs GROUP BY method")).fetchall()
                if res_m: 
                    self.ax_meth.pie([r[1] for r in res_m], labels=[r[0] for r in res_m], autopct='%1.1f%%', textprops={'color':"w"})
                self.ax_meth.set_title("MÉTODOS HTTP", fontsize=10, color="white")

                # RAM Line
                self.ax_ram.clear()
                mem = psutil.virtual_memory().percent
                self.core.ram_history.append(mem)

                if len(self.core.ram_history) > 30:
                    self.core.ram_history.pop(0)

                self.ax_ram.plot(self.core.ram_history, color='#00ff00', linewidth=2)
                self.ax_ram.set_title(f"USO DE MEMÓRIA: {mem}%", fontsize=10, color="white")
                self.ax_ram.set_ylim(0, 100)

                self.fig.tight_layout()
                self.canvas.draw()
        except Exception as e:
            logging.info(f"Erro no loop de atualização: {e}")
        finally:
            db.close()

        self.after(2000, self.update_loop)


async def start_proxy(core):
    # TODO: arquivo .env ou de configuração
    opts = Options(listen_host='0.0.0.0', listen_port=8080, mode=["regular"])
    master = DumpMaster(opts)

    class SentinelAddon:
        def request(self, flow):
            core.process_flow(flow)

        def response(self, flow):
            core.process_response(flow)
    
    master.addons.add(SentinelAddon())
    await master.run()

def thread_proxy(core):
    # TODO: O que é isso mesmo?
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if os.name != 'nt':
        try: 
            subprocess.run(["fuser", "-k", "8080/tcp"], stderr=subprocess.DEVNULL)
        except Exception as e:  
            print(f"Erro: {e}")

    loop.run_until_complete(start_proxy(core))




class TrafficFilterEngine:
    def __init__(self):
        self.truted_urls = []
        
        self.ad_domains = {
            "doubleclick.net",
            # "googlesyndication.com",
            # "adservice.google.com",
            "facebook.com",
            # "analytics.google.com"
        }


        # self.block_keywords = ["ads", "banner", "tracker", "pixel"]
        # self.block_keywords = ["ads"]
        self.block_keywords = []

    # =========================
    # REQUEST FILTER
    # =========================
    def handle_request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        url = flow.request.pretty_url

        # 🔹 Bloqueio por domínio
        if any(domain in host for domain in self.ad_domains):
            return self.block(flow, "Ad domain")

        # 🔹 Bloqueio por palavra-chave na URL
        if any(k in url.lower() for k in self.block_keywords):
            return self.block(flow, "Keyword match")

        # 🔹 Remover headers de tracking | 
        # TODO: Granularidade de quais url estão sujeitas a isso, 
        # e avisar para bloqueio ou não 

        # flow.request.headers.pop("cookie", None)
        # flow.request.headers.pop("referer", None)


    def handle_response(self, flow: http.HTTPFlow):
        content_type = flow.response.headers.get("content-type", "")

        if "text/html" in content_type:
            try:
                text = flow.response.text

                # Remover palavras simples (rápido)
                for k in self.block_keywords:
                    text = text.replace(k, "")

                flow.response.text = text
            except Exception as e:  
                print(f"Erro: {e}")

        if "application/json" in content_type:
            if "ads" in flow.request.pretty_url:
                flow.response.text = "{}"


    def block(self, flow, reason="Blocked"):
        flow.response = http.Response.make(
            403,
            f"Blocked: {reason}".encode(),
            {"Content-Type": "text/plain"}
        )


if __name__ == "__main__":
    login = ctk.CTk()
    login.title("Sentinela Auth")
    login.geometry("300x200")
    
    def auth():
        if ent.get() == "admin": #  TODO: auth
            login.destroy()
            core = NetworkCore()
            threading.Thread(target=thread_proxy, args=(core,), daemon=True).start()
            App(core).mainloop()
        else: 
            messagebox.showerror("Erro", "Senha incorreta")

    ctk.CTkLabel(login, text="ACESSO RESTRITO", font=("Arial", 14, "bold")).pack(pady=20)
    ent = ctk.CTkEntry(login, placeholder_text="Senha", show="*")
    ent.pack(pady=10)
    ctk.CTkButton(login, text="ENTRAR", command=auth).pack(pady=10)
    login.mainloop()