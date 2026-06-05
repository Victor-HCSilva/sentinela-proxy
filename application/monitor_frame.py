import ast
import json
import logging
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

    def create_key_value_tree(self, parent):
        frame = ctk.CTkFrame(parent)
        frame.pack(fill="both", expand=True)

        tree = ttk.Treeview(frame, columns=("key", "value"), show="headings")
        tree.heading("key", text="Chave")
        tree.heading("value", text="Valor")

        tree.column("key", width=250, stretch=False)
        tree.column("value", width=900)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return tree

    def create_json_tree(self, parent):
        frame = ctk.CTkFrame(parent)
        frame.pack(fill="both", expand=True)

        tree = ttk.Treeview(frame, columns=("value",), show="tree headings")
        tree.heading("#0", text="Campo")
        tree.heading("value", text="Valor")

        tree.column("#0", width=350)
        tree.column("value", width=900)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return tree

    def populate_json_tree(self, tree, parent, data):
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    node = tree.insert(parent, "end", text=str(key), values=("",))
                    self.populate_json_tree(tree, node, value)
                else:
                    tree.insert(parent, "end", text=str(key), values=(str(value),))

        elif isinstance(data, list):
            for idx, value in enumerate(data):
                if isinstance(value, (dict, list)):
                    node = tree.insert(parent, "end", text=f"[{idx}]", values=("",))
                    self.populate_json_tree(tree, node, value)
                else:
                    tree.insert(parent, "end", text=f"[{idx}]", values=(str(value),))

    def open_inspection(self, event):
        item = self.tree.selection()
        if not item:
            return

        log_id = self.tree.item(item[0])["values"][0]
        db = TrafficSessionLocal()

        try:
            log = db.query(TrafficLog).filter(TrafficLog.id == log_id).first()
            if not log:
                return

            win = ctk.CTkToplevel(self)
            win.title(f"{inspector_window.get('inspector_title')}: {log.host}")
            win.geometry(inspector_window.get("inspector_detail_size"))
            win.attributes("-topmost", True)

            # --------------------------------------------------
            # Parse headers
            # --------------------------------------------------
            headers = []
            cookies = []

            if log.headers:
                try:
                    headers_text = str(log.headers)
                    content = headers_text[len("Headers(") : -1]
                    content = ast.literal_eval(content)

                    for key, value in content:
                        key = self.encode_or_decode(key)
                        value = self.encode_or_decode(value)

                        if key.lower() == "cookie":
                            cookies.append(value)
                        else:
                            headers.append((key, value))

                except Exception as e:
                    logger.error(f"Erro ao parsear headers: {e}")

            # --------------------------------------------------
            # Tabs
            # --------------------------------------------------
            tabs = ctk.CTkTabview(win)
            tabs.pack(fill="both", expand=True, padx=10, pady=(10, 0))

            info_tab = tabs.add("Informações")
            headers_tab = tabs.add("Headers")
            cookies_tab = tabs.add("Cookies")
            body_tab = tabs.add("Body")

            # --------------------------------------------------
            # Informações
            # --------------------------------------------------
            info_frame = ctk.CTkFrame(info_tab)
            info_frame.pack(fill="x", padx=10, pady=10)

            infos = [
                ("Host", log.host),
                ("Método", log.method),
                ("Tamanho", f"{log.size:,} bytes"),
                ("Status", getattr(log, "status_code", "-")),
            ]

            for label, value in infos:
                ctk.CTkLabel(info_frame, text=f"{label}: {value}", anchor="w").pack(
                    fill="x", padx=5, pady=3
                )

            # --------------------------------------------------
            # Headers & Cookies
            # --------------------------------------------------
            headers_tree = self.create_key_value_tree(headers_tab)
            for key, value in headers:
                headers_tree.insert("", "end", values=(key, value))

            cookies_tree = self.create_key_value_tree(cookies_tab)
            for cookie in cookies:
                if "=" in cookie:
                    name, value = cookie.split("=", 1)
                else:
                    name = cookie
                    value = ""
                cookies_tree.insert("", "end", values=(name, value))

            # --------------------------------------------------
            # Payload (Processamento Robusto)
            # --------------------------------------------------
            raw_payload = log.payload
            payload = None
            texto_para_exibir = ""

            if raw_payload:
                # 1. Garantir que seja lido como string
                if isinstance(raw_payload, bytes):
                    raw_payload = raw_payload.decode("utf-8", errors="ignore")
                else:
                    raw_payload = str(raw_payload)

                texto_para_exibir = raw_payload

                # Função interna para isolar a complexidade do tratamento
                def tratar_payload(data_str):
                    # Tenta carregar como JSON diretamente
                    try:
                        return json.loads(data_str), data_str
                    except Exception:
                        pass

                    parsed_str = data_str

                    # Tenta ler a tupla python
                    try:
                        evaled = ast.literal_eval(data_str)
                        if isinstance(evaled, tuple):
                            parsed_str = "".join(evaled)
                        elif isinstance(evaled, str):
                            parsed_str = evaled
                    except SyntaxError:
                        # Se deu SyntaxError, a tupla foi cortada no meio!
                        # Vamos tentar simular o fechamento da string/tupla do Python
                        if data_str.startswith("('") or data_str.startswith('("'):
                            for close_syntax in ["')", '")']:
                                try:
                                    evaled = ast.literal_eval(data_str + close_syntax)
                                    if isinstance(evaled, tuple):
                                        parsed_str = "".join(evaled)
                                        break
                                except Exception:
                                    continue
                    except Exception:
                        pass

                    # Tenta ler o JSON após limpar a formatação da tupla
                    try:
                        return json.loads(parsed_str), parsed_str
                    except Exception:
                        pass

                    # Se o JSON estiver truncado (cortado pela metade)
                    # Forçamos o fechamento da estrutura JSON
                    closures = ['""}}}', '"}', "}}}", "}"]
                    for closure in closures:
                        try:
                            fixed_json = parsed_str + closure
                            return json.loads(fixed_json), fixed_json
                        except Exception:
                            continue

                    # Se nada funcionou, retorna a melhor versão em string encontrada
                    return None, parsed_str

                payload, texto_para_exibir = tratar_payload(raw_payload)

            # Renderizar Body
            try:
                if payload is None:
                    raise ValueError(
                        "Dados inválidos ou muito truncados para estruturar como JSON."
                    )

                json_tree = self.create_json_tree(body_tab)
                self.populate_json_tree(json_tree, "", payload)

            except Exception as e:
                logger.warning(f"Exibindo Body como texto plano: {e}")

                textbox = ctk.CTkTextbox(body_tab)
                textbox.pack(fill="both", expand=True, padx=5, pady=5)

                textbox.insert("0.0", texto_para_exibir if texto_para_exibir else "[Vazio]")
                textbox.configure(state="disabled")

            # --------------------------------------------------
            # Botão Fechar (Nova Funcionalidade)
            # --------------------------------------------------
            close_btn = ctk.CTkButton(
                win,
                text="Fechar Inspecionador",
                command=win.destroy,
                fg_color="#c0392b",
                hover_color="#96281b",
            )
            # Fica fora da área das Tabs, sempre acessível no fundo da janela
            close_btn.pack(pady=10)

        finally:
            db.close()
