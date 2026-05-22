from tkinter import ttk

import customtkinter as ctk

from configs import azul_hexadecimal, inspector_window, table, white
from database import TrafficLog, TrafficSessionLocal


class MonitorFrame(ctk.CTkFrame):
    def __init__(self, master, controller=None):
        super().__init__(master, corner_radius=0, fg_color="transparent")
        self.controller = (
            controller  # Referência ao App principal (para acessar o Core, se precisar)
        )
        self.setup_ui()

    def setup_ui(self):
        ctk.CTkLabel(
            self,
            text="Histórico de Conexões (Duplo clique para inspecionar)",
            font=ctk.CTkFont(size=15),
        ).pack(pady=10)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#2b2b2b",
            foreground=white,
            fieldbackground="#2b2b2b",
            borderwidth=0,
            font=("Arial", 10),
        )
        style.configure("Treeview.Heading", background="#333333", foreground=white, relief="flat")
        style.map("Treeview", background=[("selected", azul_hexadecimal)])

        self.tree = ttk.Treeview(self, columns=list(table.keys()), show="headings")

        for column_id, column_data in table.items():
            self.tree.heading(column_id, text=column_data["heading"]["text"])
            self.tree.column(column_id, **column_data["column"])

        self.tree.pack(fill="both", expand=True, padx=20, pady=10)
        self.tree.bind("<Double-1>", self.open_inspection)

    def open_inspection(self, event):
        item = self.tree.selection()
        if not item:
            return
        log_id = self.tree.item(item[0])["values"][0]

        # Busca no banco
        db = TrafficSessionLocal()
        try:
            log = db.query(TrafficLog).filter(TrafficLog.id == log_id).first()
            if log:
                win = ctk.CTkToplevel(self)
                win.title(f"{inspector_window.get('inspector_title')}: {log.host}")
                win.geometry(inspector_window.get("inspector_detail_size"))
                win.attributes("-topmost", True)

                box = inspector_window.get("box")
                txt = ctk.CTkTextbox(win, **box)
                txt.pack(padx=10, pady=10)

                headers_text = ""
                if log.headers:
                    try:
                        for key, value in log.headers.items():
                            if isinstance(key, bytes):
                                key = key.decode(errors="ignore")
                            if isinstance(value, bytes):
                                value = value.decode(errors="ignore")
                            headers_text += f"{key}: {value}\n"
                    except Exception:
                        headers_text = str(log.headers)

                payload = log.payload if log.payload else "[Vazio]"
                data = (
                    f"DOMÍNIO : {log.host}\n"
                    f"MÉTODO  : {log.method}\n"
                    f"TAMANHO : {log.size} bytes\n\n"
                    f"HEADERS\n{'-' * 40}\n{headers_text}\n"
                    f"PAYLOAD (BODY)\n{'-' * 40}\n{payload}"
                )
                txt.insert("0.0", data)
        finally:
            db.close()
