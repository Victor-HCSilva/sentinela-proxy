# AUXILIARES
import logging
import threading
from tkinter import messagebox, ttk

# INTERFACE
import customtkinter as ctk

# GRÁFICOS
import matplotlib.pyplot as plt
import psutil
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# DATABASE
from sqlalchemy import text

# NETWORK
from application import NetworkCore, thread_proxy

# CONFIGURAÇÕES GERAIS
from configs import (
    app_config,
    auth_labels,
    auth_window,
    azul_hexadecimal,
    ctk_button_labels,
    general_settings,
    graphs_configs,
    gray,
    green_hexadecimal,
    inspector_window,
    kill_command_message,
    table,
    vermelho_hexadecimal,
    white,
)
from database import (
    AddDomain,
    BlackList,
    BlockKeyWord,
    ConfigSessionLocal,
    Configuration,
    ExcludeHeader,
    Theme,
    TrafficLog,
    TrafficSessionLocal,
    Url,
    WhiteList,
    update_configs,
)

logger = logging.getLogger(__name__)

ctk.set_appearance_mode(general_settings.get("theme"))
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    """
    App com customtkinter estilo dark para visual mais agradável
    Visa monitorar conexões http/https e encerrar conexões
    suspeitas
    """

    def __init__(self, core):
        super().__init__()
        self.core = core
        self.after_id = None

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.running = True
        self.title(app_config.get("app_name"))
        self.geometry(app_config.get("window_size"))

        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.setup_sidebar()
        self.setup_main_frames()

        self.select_frame_by_name("dashboard")
        self.update_loop()

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
                # para loops
                self.core.shutdown()

                # cancela after pendente
                if self.after_id:
                    self.after_cancel(self.after_id)

            except Exception as e:
                logger.error(f"Erro ao fechar app: {e}")

            finally:
                self.destroy()
                import os

                os._exit(0)

        # Aguardar um instante para o usuário ver a mensagem antes de matar
        self.after(1000, do_close)

    def _toggle_theme_state(self):
        """Atualiza o texto do switch baseado no estado atual"""
        if self.theme_switch.get():
            self.theme_switch.configure(text="Ativado")
        else:
            self.theme_switch.configure(text="Desativado")

    def apply_settings(self):
        """Persiste as alterações do frame de configurações no banco de dados"""

        try:
            new_traffic = int(self.traffic_entry.get())

            new_theme = Theme.DARK if self.theme_switch.get() else Theme.LIGHT

            update_configs(traffic_visible=new_traffic, theme=new_theme)

            ctk.set_appearance_mode(new_theme.value)

            self.load_settings()

            messagebox.showinfo("Sucesso", "Configurações aplicadas com sucesso!")

        except ValueError:
            messagebox.showerror(
                "Erro", "O tráfego visível deve ser um número inteiro."
            )

        except Exception as e:
            logger.exception("Erro ao salvar configurações")

            messagebox.showerror("Erro", f"Falha ao salvar configurações:\n{e}")

    def setup_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text=app_config.get("logo_name"),
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        self.logo_label.pack(pady=30)

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
            command=self.kill_browsers,
        )
        self.btn_kill.pack(side="bottom", pady=30, padx=20)
        self.settings = ctk.CTkButton(
            self.sidebar_frame,
            text=ctk_button_labels.get("settings"),
            height=40,
            command=lambda: self.select_frame_by_name("settings"),
        )
        self.settings.pack(pady=10, padx=20)

        self.settings.configure(fg_color=azul_hexadecimal)

    def setup_main_frames(self):
        self.dash_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        self.fig, (self.ax_host, self.ax_meth, self.ax_ram) = plt.subplots(
            3, 1, figsize=(6, 12)
        )
        self.fig.patch.set_facecolor("#1a1a1a")
        for ax in [self.ax_host, self.ax_meth, self.ax_ram]:
            ax.set_facecolor("#1a1a1a")
            ax.tick_params(colors="white")
            ax.title.set_color("white")

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.dash_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)
        self.monitor_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        ctk.CTkLabel(
            self.monitor_frame,
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
        style.configure(
            "Treeview.Heading", background="#333333", foreground=white, relief="flat"
        )
        style.map("Treeview", background=[("selected", azul_hexadecimal)])

        self.tree = ttk.Treeview(
            self.monitor_frame, columns=list(table.keys()), show="headings"
        )

        # Loop para configurar cabeçalhos e colunas
        for column_id, column_data in table.items():
            heading_text = column_data["heading"]["text"]
            column_config = column_data["column"]

            self.tree.heading(column_id, text=heading_text)
            self.tree.column(column_id, **column_config)

        self.tree.pack(fill="both", expand=True, padx=20, pady=10)
        self.tree.bind("<Double-1>", self.open_inspection)

        # =====================
        # SETTINGS FRAME (REFATORADO)
        # =====================
        self.settings_frame = ctk.CTkFrame(
            self, corner_radius=0, fg_color="transparent"
        )

        ctk.CTkLabel(
            self.settings_frame,
            text="Configurações do Sistema",
            font=ctk.CTkFont(size=24, weight="bold"),
        ).pack(pady=(20, 10))

        # 1. FRAME DE OPÇÕES GERAIS (Topo)
        # Removido o expand=True para ele ocupar apenas o espaço necessário
        options_frame = ctk.CTkFrame(self.settings_frame)
        options_frame.pack(pady=10, padx=20, fill="x")

        # ===== CARREGAR CONFIG DO BANCO =====
        db = ConfigSessionLocal()
        config = db.query(Configuration).filter_by(id=1234).first()
        db.close()

        # fallback seguro
        traffic_value = config.traffic_visible if config else 100
        theme_value = config.theme.value if config and config.theme else "Dark"

        # Grid de Configurações Gerais
        options_grid = ctk.CTkFrame(options_frame, fg_color="transparent")
        options_grid.pack(pady=15, padx=20, anchor="w")

        ctk.CTkLabel(options_grid, text="Tráfego visível:").grid(
            row=0, column=0, pady=10, padx=(0, 20), sticky="w"
        )

        self.traffic_entry = ctk.CTkEntry(options_grid, width=150)
        self.traffic_entry.grid(row=0, column=1, pady=10, sticky="w")
        self.traffic_entry.insert(0, str(traffic_value))

        ctk.CTkLabel(options_grid, text="Tema escuro:").grid(
            row=1, column=0, pady=10, padx=(0, 20), sticky="w"
        )

        self.theme_switch = ctk.CTkSwitch(
            options_grid, text="Ativado", command=self._toggle_theme_state
        )
        self.theme_switch.grid(row=1, column=1, pady=10, sticky="w")

        if theme_value == "Dark":
            self.theme_switch.select()
        else:
            self.theme_switch.deselect()

        self._toggle_theme_state()

        ctk.CTkButton(
            options_grid,
            text="Confirmar alterações",
            fg_color=green_hexadecimal,
            command=self.apply_settings,
        ).grid(row=2, column=0, columnspan=2, pady=(20, 10), sticky="w")

        self._pending_theme = "Dark" if self.theme_switch.get() else "Light"

        # 2. FRAME DE GERENCIAMENTO DE LISTAS (Base - ocupa o restante da tela)
        self.setup_management_tab()
        self.refresh_mgmt_list()

    def setup_management_tab(self):
        """Cria a interface para gerenciar listas (Whitelist, Blacklist, Words)"""
        self.mgmt_frame = ctk.CTkFrame(self.settings_frame)
        self.mgmt_frame.pack(pady=10, padx=20, fill="both", expand=True)

        ctk.CTkLabel(
            self.mgmt_frame,
            text="Gerenciamento de Regras",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(pady=(15, 5), anchor="w", padx=20)

        # Barra de Ações (Categoria -> Input -> Botão) em uma única linha
        action_bar = ctk.CTkFrame(self.mgmt_frame, fg_color="transparent")
        action_bar.pack(fill="x", padx=20, pady=10)

        self.category_var = ctk.StringVar(value="URLs")
        categories = [
            "URLs",
            "Palavras Bloqueadas",
            "Blacklist",
            "Whitelist",
            "Domínios de Anúncio",
            "Headers Excluídos",
        ]

        selector = ctk.CTkOptionMenu(
            action_bar,
            values=categories,
            variable=self.category_var,
            command=self.refresh_mgmt_list,
            width=180,
        )
        selector.pack(side="left", padx=(0, 10))

        self.new_entry = ctk.CTkEntry(
            action_bar, placeholder_text="Digite o novo valor aqui..."
        )
        self.new_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        add_btn = ctk.CTkButton(
            action_bar,
            text="Adicionar",
            fg_color=green_hexadecimal,
            command=self.add_to_list,
            width=100,
        )
        add_btn.pack(side="right")

        # Lista visual (Listbox scrollable)
        self.items_listbox = ctk.CTkScrollableFrame(self.mgmt_frame)
        self.items_listbox.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    def add_to_list(self):
        val = self.new_entry.get().strip()
        category = self.category_var.get()

        if not val:
            return

        db = ConfigSessionLocal()

        try:
            # =====================
            # BLACKLIST / WHITELIST / ADS
            # =====================
            if category in ["Blacklist", "Whitelist", "Domínios de Anúncio"]:
                url_obj = db.query(Url).filter_by(url=val).first()

                if not url_obj:
                    url_obj = Url(url=val)
                    db.add(url_obj)
                    db.flush()

                model = {
                    "Blacklist": BlackList,
                    "Whitelist": WhiteList,
                    "Domínios de Anúncio": AddDomain,
                }[category]

                exists = db.query(model).filter_by(url_id=url_obj.id).first()

                if not exists:
                    db.add(model(url_id=url_obj.id))

            # =====================
            # PALAVRAS BLOQUEADAS
            # =====================
            elif category == "Palavras Bloqueadas":
                exists = db.query(BlockKeyWord).filter_by(word=val).first()

                if not exists:
                    db.add(BlockKeyWord(word=val))

            # =====================
            # HEADERS EXCLUÍDOS
            # =====================
            elif category == "Headers Excluídos":
                exists = db.query(ExcludeHeader).filter_by(field_name=val).first()

                if not exists:
                    db.add(ExcludeHeader(field_name=val))

            # =====================
            # URLS
            # =====================
            elif category == "URLs":
                exists = db.query(Url).filter_by(url=val).first()

                if not exists:
                    db.add(Url(url=val))

            db.commit()

            self.new_entry.delete(0, "end")

            self.refresh_mgmt_list()

            self.core.load_configs()

            messagebox.showinfo("Sucesso", "Valor adicionado com sucesso!")

        except Exception as e:
            db.rollback()

            messagebox.showerror("Erro", f"Não foi possível adicionar:\n{e}")

        finally:
            db.close()

    def toggle_theme(self, switch):
        """Alterna entre tema claro e escuro"""
        if switch.get():
            ctk.set_appearance_mode("Dark")
            switch.configure(text="Ativado")
        else:
            ctk.set_appearance_mode("Light")
            switch.configure(text="Desativado")

    # def save_settings(self, traffic_amount, theme_state):
    #     """Salva as configurações no banco de dados"""

    #     try:
    #         amount = int(traffic_amount)

    #         # Define o tema baseado no switch
    #         if theme_state:
    #             selected_theme = Theme.DARK
    #         else:
    #             selected_theme = Theme.LIGHT

    #         # Salva no banco
    #         update_configs(
    #             traffic_visible=amount,
    #             theme=selected_theme
    #         )

    #         # Atualiza visualmente
    #         ctk.set_appearance_mode(selected_theme.value)

    #         messagebox.showinfo(
    #             "Sucesso",
    #             "Configurações salvas com sucesso!"
    #         )

    #         self.load_settings()
    #     except ValueError:
    #         messagebox.showerror(
    #             "Erro",
    #             "Digite um número válido para quantidade de tráfego"
    #         )

    #     except Exception as e:
    #         messagebox.showerror(
    #             "Erro",
    #             f"Falha ao salvar configurações:\n{e}"
    #         )

    def select_frame_by_name(self, name):
        # Resetar cores dos botões
        self.btn_dash.configure(fg_color=gray)
        self.btn_monitor.configure(fg_color=gray)
        self.settings.configure(fg_color=gray)

        # Esconder todos os frames (verificando se existem)
        if hasattr(self, "dash_frame"):
            self.dash_frame.grid_forget()
        if hasattr(self, "monitor_frame"):
            self.monitor_frame.grid_forget()
        if hasattr(self, "settings_frame"):
            self.settings_frame.grid_forget()

        # Mostrar frame selecionado
        if name == "dashboard":
            self.btn_dash.configure(fg_color=azul_hexadecimal)
            if hasattr(self, "dash_frame"):
                self.dash_frame.grid(row=0, column=1, sticky="nsew")
        elif name == "monitor":
            self.btn_monitor.configure(fg_color=azul_hexadecimal)
            if hasattr(self, "monitor_frame"):
                self.monitor_frame.grid(row=0, column=1, sticky="nsew")
        elif name == "settings":
            if hasattr(self, "settings_frame"):
                self.settings.configure(fg_color=azul_hexadecimal)
                self.settings_frame.grid(row=0, column=1, sticky="nsew")

    def open_inspection(self, event):
        item = self.tree.selection()
        if not item:
            return
        log_id = self.tree.item(item[0])["values"][0]

        db = TrafficSessionLocal()
        log = db.query(TrafficLog).filter(TrafficLog.id == log_id).first()
        db.close()

        if log:
            box = inspector_window.get("box")

            win = ctk.CTkToplevel(self)
            win.title(f"{inspector_window.get('inspector_title')}: {log.host}")
            win.geometry(inspector_window.get("inspector_detail_size"))
            win.attributes("-topmost", True)

            txt = ctk.CTkTextbox(win, **box)
            txt.pack(padx=10, pady=10)

            # NOTE: Aqui a visualização dos dados em detalhe
            data = f"DOMÍNIO: {log.host}\nMÉTODO: {log.method}\nTAMANHO: {log.size} bytes\n"
            data += f"\n--- HEADERS ---\n{log.headers}\n"
            data += (
                f"\n--- PAYLOAD (BODY) ---\n{log.payload if log.payload else '[Vazio]'}"
            )
            txt.insert("0.0", data)

    def load_settings(self):
        """Carrega configurações do banco"""

        db = ConfigSessionLocal()

        try:
            config = db.query(Configuration).filter_by(id=1234).first()

            if config:
                # Quantidade de tráfego
                self.traffic_entry.delete(0, "end")
                self.traffic_entry.insert(0, str(config.traffic_visible))

                # Tema
                if config.theme == Theme.DARK:
                    ctk.set_appearance_mode("Dark")
                    self.theme_switch.select()
                    self.theme_switch.configure(text="Ativado")

                else:
                    ctk.set_appearance_mode("Light")
                    self.theme_switch.deselect()
                    self.theme_switch.configure(text="Desativado")

        finally:
            db.close()

    def kill_browsers(self):
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

    def refresh_mgmt_list(self, _=None):
        for widget in self.items_listbox.winfo_children():
            widget.destroy()

        category = self.category_var.get()

        # Mapeamento atualizado
        model_map = {
            "URLs": (Url, "url"),
            "Palavras Bloqueadas": (BlockKeyWord, "word"),
            "Blacklist": (BlackList, "url"),  # Nota: aqui usamos o relacionamento
            "Whitelist": (WhiteList, "url"),
            "Domínios de Anúncio": (AddDomain, "url"),
            "Headers Excluídos": (ExcludeHeader, "field_name"),
        }

        model, attr = model_map.get(category)
        from database import Repository

        repo = Repository(model)
        items = repo.get_all()

        for item in items:
            val = getattr(item, attr)
            if hasattr(val, "url"):
                val = val.url

            # Frame da linha com leve tom de contraste (opcional)
            row = ctk.CTkFrame(self.items_listbox, fg_color="#2b2b2b", corner_radius=5)
            row.pack(fill="x", pady=3, padx=2)

            ctk.CTkLabel(row, text=val, anchor="w").pack(
                side="left", padx=15, pady=5, expand=True, fill="x"
            )

            ctk.CTkButton(
                row,
                text="Excluir",
                width=70,
                height=26,
                fg_color=vermelho_hexadecimal,
                hover_color="#7b241c",
                command=lambda i=item.id, m=model: self.delete_mgmt_item(i, m),
            ).pack(
                side="right", padx=15, pady=5
            )  # Padding maior na direita para não conflitar com a barra de scroll

    def delete_mgmt_item(self, item_id, model):
        """Remove um item do banco e atualiza a interface e o Core"""
        from database import Repository

        repo = Repository(model)

        if repo.delete(item_id):
            self.refresh_mgmt_list()
            # Notifica o proxy para atualizar as listas em memória imediatamente
            self.core.load_configs()
        else:
            messagebox.showerror("Erro", "Não foi possível excluir o item.")

    def update_loop(self):
        if not self.running:
            return

        db_config = ConfigSessionLocal()
        db_traffic = TrafficSessionLocal()

        try:
            config = db_config.query(Configuration).filter_by(id=1234).first()

            quantidade_de_trafegos_visiveis = (
                config.traffic_visible
                if config
                else general_settings.get("amount_of_visible_traffic")
            )

            pie_conf = graphs_configs.get("pie")
            barh_conf = graphs_configs.get("barh")
            line_conf = graphs_configs.get("line")

            logs = (
                db_traffic.query(TrafficLog)
                .order_by(TrafficLog.id.desc())
                .limit(quantidade_de_trafegos_visiveis)
                .all()
            )

            self.tree.delete(*self.tree.get_children())

            for log in logs:
                self.tree.insert(
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

            if self.dash_frame.winfo_ismapped():
                self.ax_host.clear()
                res_h = db_traffic.execute(text(barh_conf.get("query"))).fetchall()

                if res_h:
                    self.ax_host.barh(
                        [r[0][:20] for r in res_h],
                        [r[1] for r in res_h],
                        color=azul_hexadecimal,
                    )

                self.ax_host.set_title(
                    barh_conf.get("title"),
                    fontsize=barh_conf.get("font_size"),
                    color=barh_conf.get("text_color"),
                )

                self.ax_meth.clear()
                res_m = db_traffic.execute(text(pie_conf.get("query"))).fetchall()

                if res_m:
                    self.ax_meth.pie(
                        [r[1] for r in res_m],
                        labels=[r[0] for r in res_m],
                        autopct="%1.1f%%",
                        textprops={"color": pie_conf.get("text_color")},
                    )

                self.ax_meth.set_title(
                    pie_conf.get("title"),
                    fontsize=pie_conf.get("font_size"),
                    color=pie_conf.get("text_color"),
                )

                self.ax_ram.clear()

                mem = psutil.virtual_memory().percent
                self.core.ram_history.append(mem)

                if len(self.core.ram_history) > 30:
                    self.core.ram_history.pop(0)

                self.ax_ram.plot(
                    self.core.ram_history,
                    color=green_hexadecimal,
                    linewidth=2,
                )

                self.ax_ram.set_title(
                    f"{line_conf.get('title')} {mem}%",
                    fontsize=line_conf.get("font_size"),
                    color=line_conf.get("text_color"),
                )

                self.ax_ram.set_ylim(0, 100)

                self.fig.tight_layout()
                self.canvas.draw()

        except Exception as e:
            logger.error(f"Erro no loop de atualização: {e}")

        finally:
            db_config.close()
            db_traffic.close()

        if self.core.running:
            self.after_id = self.after(2000, self.update_loop)


if __name__ == "__main__":
    login = ctk.CTk()
    login.title(auth_window.get("auth_title"))
    login.geometry(auth_window.get("window_size"))

    def auth():
        if ent.get() == "admin":
            login.destroy()
            core = NetworkCore()
            threading.Thread(target=thread_proxy, args=(core,), daemon=True).start()
            App(core).mainloop()
        else:
            msg_config = auth_labels.get("incorret_password_message")
            messagebox.showerror(
                title=msg_config.get("context_title"), message=msg_config.get("message")
            )

    ctk.CTkLabel(
        login, text=auth_labels.get("content_title"), font=auth_labels.get("font")
    ).pack(pady=20)
    ent = ctk.CTkEntry(
        login, placeholder_text=auth_labels.get("placeholder_text"), show="*"
    )
    ent.pack(pady=10)
    ctk.CTkButton(login, text=ctk_button_labels.get("login"), command=auth).pack(
        pady=10
    )
    login.mainloop()
