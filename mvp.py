import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import asyncio
import os
import subprocess
import logging
import psutil
import random
from datetime import datetime
import tempfile

# Bibliotecas de Terceiros
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, text
from sqlalchemy.orm import sessionmaker, declarative_base

# Importações mitmproxy
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# =========================
# DATABASE & LOGS
# =========================
Base = declarative_base()
# Salvando o banco no diretório temporário para evitar erros de permissão
db_path = os.path.join(tempfile.gettempdir() if os.name != 'nt' else "C:/temp", "sentinela_v4.db")
if not os.path.exists(os.path.dirname(db_path)):
    db_path = "sentinela_v4.db" # Fallback para diretório local

engine = create_engine(f'sqlite:///{db_path}', connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class TrafficLog(Base):
    __tablename__ = 'traffic_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now)
    host = Column(String)
    method = Column(String)
    size = Column(Integer)
    path = Column(Text)

class Anomaly(Base):
    __tablename__ = 'anomalies'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now)
    description = Column(String)
    host = Column(String)

# Criar as tabelas corretamente
Base.metadata.create_all(bind=engine)

# =========================
# MOTOR DE ANÁLISE (CORE)
# =========================
class NetworkCore:
    def __init__(self):
        self.blacklist = set()
        self.limits = {"max_payload": 102400, "block_tracking": True} # 100KB padrão
        self.stats = {"total_reqs": 0, "alerts": 0}

    def save_log_data(self, flow: http.HTTPFlow):
        """Salva a conexão no banco de dados SQLite"""
        db = SessionLocal()
        try:
            size = len(flow.request.content) if flow.request.content else 0
            log = TrafficLog(
                host=flow.request.pretty_host,
                method=flow.request.method,
                path=flow.request.path,
                size=size
            )
            db.add(log)
            db.commit()
            self.stats["total_reqs"] += 1
        except Exception as e:
            print(f"Erro ao salvar log: {e}")
        finally:
            db.close()

    def analysis(self, flow: http.HTTPFlow):
        """Lógica de firewall e detecção de anomalias"""
        host = flow.request.pretty_host
        size = len(flow.request.content) if flow.request.content else 0

        # 1. Bloqueio por Blacklist
        if host in self.blacklist:
            self.create_alert(f"ACESSO BLOQUEADO (Blacklist): {host}", host)
            flow.kill()
            return

        # 2. Payload Excessivo
        if size > self.limits["max_payload"]:
            self.create_alert(f"Payload Suspeito: {size} bytes", host)

        # 3. Tracking/Ads
        if self.limits["block_tracking"] and any(x in host for x in ["ads.", "track.", "analytics."]):
            self.create_alert(f"Bloqueio de rastreamento: {host}", host)
            flow.kill()

    def create_alert(self, msg, host):
        db = SessionLocal()
        try:
            new_alert = Anomaly(description=msg, host=host)
            db.add(new_alert)
            db.commit()
            self.stats["alerts"] += 1
        finally:
            db.close()

# =========================
# INTERFACE GRÁFICA (GUI)
# =========================
class App:
    def __init__(self, root, core):
        self.root = root
        self.core = core
        self.root.title("Sentinela Network Monitor v4.0")
        self.root.geometry("1000x700")

        self.setup_ui()
        self.update_loop()

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)

        # ABA 1: DASHBOARD
        self.tab_dash = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dash, text="Dashboard")
        
        self.fig, self.ax = plt.subplots(figsize=(6, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab_dash)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)

        # ABA 2: CONEXÕES
        self.tab_conn = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_conn, text="Conexões Ativas")
        
        cols = ("ID", "HORA", "MÉTODO", "HOST", "TAMANHO")
        self.tree = ttk.Treeview(self.tab_conn, columns=cols, show='headings')
        for col in cols: self.tree.heading(col, text=col)
        self.tree.column("HOST", width=400)
        self.tree.pack(fill='both', expand=True, padx=10, pady=10)
        
        ttk.Button(self.tab_conn, text="Bloquear Host Selecionado", command=self.block_host).pack(pady=5)

        # ABA 3: CONFIGURAÇÕES
        self.tab_config = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_config, text="Painel de Controle")
        
        frame_cfg = ttk.LabelFrame(self.tab_config, text=" Limites do Firewall ", padding=20)
        frame_cfg.pack(padx=20, pady=20, fill='x')
        
        ttk.Label(frame_cfg, text="Limite de Payload (Bytes):").pack(side='left')
        self.ent_payload = ttk.Entry(frame_cfg)
        self.ent_payload.insert(0, str(self.core.limits["max_payload"]))
        self.ent_payload.pack(side='left', padx=10)
        
        ttk.Button(frame_cfg, text="Salvar", command=self.save_cfg).pack(side='left')

    def block_host(self):
        selected = self.tree.selection()
        if selected:
            host = self.tree.item(selected[0])['values'][3]
            self.core.blacklist.add(host)
            messagebox.showwarning("Firewall", f"Host {host} foi bloqueado!")

    def save_cfg(self):
        try:
            self.core.limits["max_payload"] = int(self.ent_payload.get())
            messagebox.showinfo("Sucesso", "Configurações aplicadas.")
        except:
            messagebox.showerror("Erro", "Valor inválido.")

    def update_loop(self):
        db = SessionLocal()
        # 1. Atualizar Tabela
        logs = db.query(TrafficLog).order_by(TrafficLog.id.desc()).limit(20).all()
        self.tree.delete(*self.tree.get_children())
        for l in logs:
            self.tree.insert("", "end", values=(l.id, l.timestamp.strftime("%H:%M:%S"), l.method, l.host, l.size))

        # 2. Atualizar Gráfico (Top 5 hosts)
        self.ax.clear()
        results = db.execute(text("SELECT host, COUNT(id) as total FROM traffic_logs GROUP BY host ORDER BY total DESC LIMIT 5")).fetchall()
        if results:
            hosts = [r[0][:15] for r in results]
            vals = [r[1] for r in results]
            self.ax.bar(hosts, vals, color='teal')
            self.ax.set_title("Top 5 Domínios Interceptados")
        self.canvas.draw()
        
        db.close()
        self.root.after(3000, self.update_loop)

# =========================
# MITMPROXY INTEGRATION
# =========================
class SentinelaAddon:
    def __init__(self, core):
        self.core = core

    def request(self, flow: http.HTTPFlow):
        # Ignorar o próprio tráfego de interface
        if flow.request.pretty_host in ["localhost", "127.0.0.1"]:
            return
        self.core.save_log_data(flow)
        self.core.analysis(flow)

async def start_proxy(core):
    opts = Options(listen_host='0.0.0.0', listen_port=8080, mode=["regular"])
    master = DumpMaster(opts)
    master.addons.add(SentinelaAddon(core))
    await master.run()

def run_proxy_thread(core):
    # Tenta limpar a porta no Linux/Mac
    if os.name != 'nt':
        try: subprocess.run(["fuser", "-k", "8080/tcp"], stderr=subprocess.DEVNULL)
        except: pass
    
    asyncio.run(start_proxy(core))

# =========================
# LOGIN & MAIN
# =========================
def login():
    root = tk.Tk()
    root.withdraw()
    # Mock de login (admin/admin)
    pwd = simpledialog.askstring("Sentinela Auth", "Senha de Administrador:", show="*")
    root.destroy()
    return pwd == "admin"

if __name__ == "__main__":
    if login():
        core = NetworkCore()
        
        # Iniciar Proxy em Background
        threading.Thread(target=run_proxy_thread, args=(core,), daemon=True).start()
        
        # Iniciar Interface
        root = tk.Tk()
        app = App(root, core)
        root.mainloop()
    else:
        print("Acesso negado.")
