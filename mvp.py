import tkinter as tk
from tkinter import ttk
import threading
import asyncio
from datetime import datetime
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# =========================
# MOTOR DE ANÁLISE (CORE)
# =========================
class NetworkCore:
    def __init__(self):
        self.connections = []
        self.alerts = []
        self.stats = {"total": 0, "alerts": 0}

    def process_flow(self, flow: http.HTTPFlow):
        try:
            host = flow.request.pretty_host
        except:
            return

        # Evitar loop infinito se acessar o próprio proxy no navegador
        if host in ["127.0.0.1", "localhost", "0.0.0.0"]:
            flow.response = http.Response.make(
                200, 
                b"<h1>Sentinela Ativo</h1><p>O proxy esta funcionando e capturando trafego.</p>",
                {"Content-Type": "text/html"}
            )
            return

        size = len(flow.request.content) if flow.request.content else 0
        conn_data = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "meth": flow.request.method,
            "host": host,
            "size": f"{size} B"
        }
        
        self.connections.append(conn_data)
        self.stats["total"] += 1

        # Regra de Alerta Simples
        if size > 100000: # 100KB
            self.alerts.append(f"[{conn_data['time']}] Payload Grande: {host}")
            self.stats["alerts"] += 1

        if len(self.connections) > 25: self.connections.pop(0)

# =========================
# ADDON DO MITMPROXY
# =========================
class MonitorAddon:
    def __init__(self, core):
        self.core = core

    def request(self, flow: http.HTTPFlow):
        self.core.process_flow(flow)

# =========================
# INTERFACE GRÁFICA (GUI)
# =========================
class App:
    def __init__(self, root, core):
        self.root = root
        self.core = core
        self.root.title("Monitor Sentinela v3.1 - HTTPS Security")
        self.root.geometry("800x550")
        
        # Cabeçalho
        frame_top = tk.Frame(root, pady=10)
        frame_top.pack(fill='x')
        self.lbl_status = tk.Label(frame_top, text="● PROXY ATIVO (Porta 8080)", fg="green", font=("Arial", 10, "bold"))
        self.lbl_status.pack(side='left', padx=20)
        
        self.lbl_stats = tk.Label(frame_top, text="Requisições: 0", font=("Arial", 10))
        self.lbl_stats.pack(side='right', padx=20)

        # Tabela de Conexões
        self.tree = ttk.Treeview(root, columns=("T", "M", "H", "S"), show='headings')
        self.tree.heading("T", text="Hora")
        self.tree.heading("M", text="Método")
        self.tree.heading("H", text="Host")
        self.tree.heading("S", text="Tamanho")
        self.tree.column("T", width=100); self.tree.column("M", width=80)
        self.tree.column("H", width=400); self.tree.column("S", width=100)
        self.tree.pack(fill='both', expand=True, padx=15)

        # Área de Alertas
        tk.Label(root, text="Alertas de Segurança:", font=("Arial", 9, "bold")).pack(anchor='w', padx=15, pady=(10,0))
        self.txt_alerts = tk.Text(root, height=8, bg="#1a1a1a", fg="#ff9800", font=("Consolas", 10))
        self.txt_alerts.pack(fill='x', padx=15, pady=10)
        
        self.update_ui_loop()

    def update_ui_loop(self):
        # Atualizar Tabela
        self.tree.delete(*self.tree.get_children())
        for c in reversed(self.core.connections):
            self.tree.insert("", "end", values=(c['time'], c['meth'], c['host'], c['size']))
        
        # Atualizar Alertas e Stats
        self.lbl_stats.config(text=f"Total: {self.core.stats['total']} | Alertas: {self.core.stats['alerts']}")
        self.txt_alerts.delete(1.0, tk.END)
        for a in self.core.alerts[-10:]:
            self.txt_alerts.insert(tk.END, a + "\n")
            
        self.root.after(1000, self.update_ui_loop)

# =========================
# FUNÇÃO DO PROXY (THREAD)
# =========================
def start_proxy_thread(core):
    async def run_proxy():
        opts = Options(listen_host='0.0.0.0', listen_port=8080, mode=["regular"])
        # IMPORTANTE: Criar o DumpMaster aqui dentro, onde o loop já existe
        master = DumpMaster(opts)
        master.addons.add(MonitorAddon(core))
        
        try:
            await master.run()
        except Exception as e:
            print(f"Erro no Proxy: {e}")

    # Cria um novo loop asyncio para esta thread
    asyncio.run(run_proxy())

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    core = NetworkCore()
    
    # Inicia o proxy em uma thread separada
    t = threading.Thread(target=start_proxy_thread, args=(core,), daemon=True)
    t.start()
    
    # Inicia a Interface Gráfica
    root = tk.Tk()
    app = App(root, core)
    
    print("Iniciando interface... Proxy rodando em 0.0.0.0:8080")
    root.mainloop()
