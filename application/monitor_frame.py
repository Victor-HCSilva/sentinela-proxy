import ast
import json
import logging
from pprint import pprint
from tkinter import ttk

import customtkinter as ctk

from configs import azul_hexadecimal, inspector_window, table, white
from database import TrafficLog, TrafficSessionLocal

logger = logging.getLogger(__name__)


class MonitorFrame(ctk.CTkFrame):
    def __init__(self, master, controller=None):
        super().__init__(master, corner_radius=0, fg_color="transparent")
        self.controller = controller
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

    def encode_or_decode(self, value: bytes, encoding: str = "utf-8", encode: bool = True) -> str:
        if encode and isinstance(value, bytes):
            return value.decode(errors="ignore")
        if not encode and isinstance(value, str):
            return value.encode(encoding, errors="ignore")
        return str(value)

    def open_inspection(self, event):
        number_of_strokes = 40
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

                if log.headers is not None:
                    headers_text = str(log.headers)
                    content: str = headers_text[len("Headers(") : -1]
                    content: tuple[bytes, bytes] = ast.literal_eval(content)

                    try:
                        headers_dict = {}

                        for tuple_value in content:
                            key, value = tuple_value
                            key = self.encode_or_decode(key)
                            value = self.encode_or_decode(value)
                            headers_dict[key.upper()] = value
                        headers_text = "\n".join(
                            [f"{key}: {value}" for key, value in headers_dict.items()]
                        )

                    except Exception as e:
                        logger.error(f"Erro ao tentar parsear headers: {e}")

                try:
                    payload: dict = ast.literal_eval(log.payload)
                    payload_text = json.dumps(payload, indent=4)
                    payload_text = payload_text.replace("\n", "\n" + " " * number_of_strokes)
                except Exception as e:
                    logger.error(f"Erro ao tentar parsear payload: {e}")
                    payload_text = log.payload if log.payload else "[Vazio]"

                data = (
                    f"DOMÍNIO : {log.host}\n"
                    f"MÉTODO  : {log.method}\n"
                    f"TAMANHO : {log.size} bytes\n\n"
                    f"HEADERS\n{'-' * number_of_strokes}\n{headers_text}\n"
                    f"{number_of_strokes * '-'}\n"
                    f"PAYLOAD (BODY)\n{'-' * number_of_strokes}\n{payload_text}"
                )
                txt.insert("0.0", data)
        finally:
            db.close()
