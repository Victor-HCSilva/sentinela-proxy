import logging
import customtkinter as ctk
from tkinter import ttk, messagebox
import threading
import asyncio
import os
import subprocess
import psutil

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sqlalchemy import text

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster


from application import NetworkCore 
from database import (
    SessionLocal, 
    TrafficLog, 
    Configuration,
    Url,
    AddDomain,
    BlockKeyWord,
    BlackList,
    WhiteList,
    ExcludeHeader,
    populate,
    is_empty,
    update_configs,
    Theme,
) 

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
    azul_hexadecimal,
    vermelho_hexadecimal,
    green_hexadecimal,
    gray,
    fake_infos,
)

logger = logging.getLogger(__name__)

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
            
            # Aplica o tema visualmente na hora
            ctk.set_appearance_mode(new_theme.value)
            
            messagebox.showinfo("Sucesso", "Configurações aplicadas com sucesso!")
        except ValueError:
            messagebox.showerror("Erro", "O tráfego visível deve ser um número inteiro.")
        
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
        self.settings = ctk.CTkButton(
            self.sidebar_frame,
            text=ctk_button_labels.get("settings"),
            height=40,
            command=lambda: self.select_frame_by_name("settings")
        )
        self.settings.pack(pady=10, padx=20)

        self.settings.configure(fg_color=azul_hexadecimal)




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

        # FRAME SETTINGS
        # =====================
        # SETTINGS FRAME (REFATORADO)
        # =====================
        self.settings_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        ctk.CTkLabel(
            self.settings_frame,
            text="Configurações do Sistema",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)

        options_frame = ctk.CTkFrame(self.settings_frame, fg_color="transparent")
        options_frame.pack(pady=20, padx=40, fill="both", expand=True)

        # ===== CARREGAR CONFIG DO BANCO =====
        db = SessionLocal()
        config = db.query(Configuration).filter_by(id=1234).first()
        db.close()

        # fallback seguro
        traffic_value = config.traffic_visible if config else 100
        theme_value = config.theme.value if config else "Dark"

        # =====================
        # TRAFFIC INPUT
        # =====================
        ctk.CTkLabel(options_frame, text="Tráfego visível:").grid(
            row=0, column=0, pady=10, sticky="w"
        )

        self.traffic_entry = ctk.CTkEntry(options_frame)
        self.traffic_entry.grid(row=0, column=1, pady=10, padx=20)
        self.traffic_entry.insert(0, str(traffic_value))

        # =====================
        # THEME SWITCH
        # =====================
        ctk.CTkLabel(options_frame, text="Tema escuro:").grid(
            row=1, column=0, pady=10, sticky="w"
        )

        self.theme_switch = ctk.CTkSwitch(
            options_frame,
            text="Ativado",
            command=self._toggle_theme_state
        )
        self.theme_switch.grid(row=1, column=1, pady=10, padx=20)

        if theme_value == "Dark":
            self.theme_switch.select()
        else:
            self.theme_switch.deselect()

        # =====================
        # BOTÃO CONFIRMAR
        # =====================
        ctk.CTkButton(
            options_frame,
            text="Confirmar alterações",
            fg_color=green_hexadecimal,
            command=self.apply_settings
        ).grid(row=2, column=0, columnspan=2, pady=30)

        # estado temporário (NÃO SALVA AINDA)
        self._pending_theme = "Dark" if self.theme_switch.get() else "Light"
# Dentro de setup_main_frames, no final da seção de SETTINGS
        self.setup_management_tab()
# Carrega a lista inicial (URLs por padrão)
        self.refresh_mgmt_list()


# No app.py, dentro do setup_main_frames ou em um método dedicado
    def setup_management_tab(self):
        """Cria a interface para gerenciar listas (Whitelist, Blacklist, Words)"""
        self.mgmt_frame = ctk.CTkFrame(self.settings_frame)
        self.mgmt_frame.pack(pady=10, padx=20, fill="both", expand=True)

        # Seletor de qual categoria gerenciar
        self.category_var = ctk.StringVar(value="URLs")
        categories = ["URLs", "Palavras Bloqueadas", "Blacklist", "Whitelist"]
        
        selector = ctk.CTkOptionMenu(
            self.mgmt_frame, 
            values=categories,
            variable=self.category_var,
            command=self.refresh_mgmt_list
        )
        selector.pack(pady=10)

        # Campo de entrada para novos valores
        self.new_entry = ctk.CTkEntry(self.mgmt_frame, placeholder_text="Novo valor...")
        self.new_entry.pack(side="left", padx=10, pady=10, expand=True, fill="x")

        add_btn = ctk.CTkButton(
            self.mgmt_frame, text="Adicionar", 
            fg_color=green_hexadecimal,
            command=self.add_to_list
        )
        add_btn.pack(side="right", padx=10)

        # Lista visual (Listbox ou similar)
        self.items_listbox = ctk.CTkScrollableFrame(self.mgmt_frame, height=200)
        self.items_listbox.pack(fill="both", expand=True, padx=10, pady=10)


    def add_to_list(self):

        val = self.new_entry.get().strip()
        category = self.category_var.get()
        if not val: return

        db = SessionLocal()
        try:
            # Caso especial: tabelas que usam URL
            if category in ["Blacklist", "Whitelist", "Domínios"]:
                url_obj = db.query(Url).filter_by(url=val).first()
                if not url_obj:
                    url_obj = Url(url=val)
                    db.add(url_obj)
                    db.commit()
                
                # Mapeia para o modelo correto
                model = {"Blacklist": BlackList, "Whitelist": WhiteList, "Domínios": AddDomain}[category]
                # Criamos a instância manualmente com o objeto relacionado
                new_item = model(url_id=url_obj.id)
                db.add(new_item)
                db.commit()
            
            elif category == "Palavras Bloqueadas":
                db.add(BlockKeyWord(word=val))
                db.commit()

            elif category == "URLs":
                db.add(Url(url=val))
                db.commit()

            self.new_entry.delete(0, 'end')
            self.refresh_mgmt_list()
            self.core.load_configs()
        except Exception as e:
            db.rollback()
            messagebox.showerror("Erro", f"Falha ao salvar: {e}")
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

    def save_settings(self, traffic_amount, theme_state):
        """Salva as configurações"""
        try:
            # Atualizar configurações (você precisará persistir isso)
            amount = int(traffic_amount)
            # Aqui você pode salvar em um arquivo config.json ou similar
            
            messagebox.showinfo("Sucesso", "Configurações salvas! Reinicie para aplicar todas as alterações.")
        except ValueError:
            messagebox.showerror("Erro", "Digite um número válido para quantidade de tráfego")


    def select_frame_by_name(self, name):
        # Resetar cores dos botões
        self.btn_dash.configure(fg_color=gray)
        self.btn_monitor.configure(fg_color=gray)
        self.settings.configure(fg_color=gray)
        
        # Esconder todos os frames (verificando se existem)
        if hasattr(self, 'dash_frame'):
            self.dash_frame.grid_forget()
        if hasattr(self, 'monitor_frame'):
            self.monitor_frame.grid_forget()
        if hasattr(self, 'settings_frame'):
            self.settings_frame.grid_forget()
        
        # Mostrar frame selecionado
        if name == "dashboard":
            self.btn_dash.configure(fg_color=azul_hexadecimal)
            if hasattr(self, 'dash_frame'):
                self.dash_frame.grid(row=0, column=1, sticky="nsew")
        elif name == "monitor":
            self.btn_monitor.configure(fg_color=azul_hexadecimal)
            if hasattr(self, 'monitor_frame'):
                self.monitor_frame.grid(row=0, column=1, sticky="nsew")
        elif name == "settings":
            if hasattr(self, 'settings_frame'):
                self.settings.configure(fg_color=azul_hexadecimal)
                self.settings_frame.grid(row=0, column=1, sticky="nsew")


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

    def refresh_mgmt_list(self, _=None):
        """Atualiza a visualização dos itens da categoria selecionada"""
        # Limpa a lista atual
        for widget in self.items_listbox.winfo_children():
            widget.destroy()

        category = self.category_var.get()
        
        # Mapeamento para saber qual atributo ler de cada modelo
        model_map = {
            "URLs": (Url, "url"),
            "Palavras Bloqueadas": (BlockKeyWord, "word"),
            "Blacklist": (BlackList, "domain"),
            "Whitelist": (WhiteList, "domain"),
            "Domínios": (AddDomain, "domain"),
            "Headers Excluídos": (ExcludeHeader, "header_name")
        }

        model, attr_name = model_map.get(category)
        from database import Repository
        repo = Repository(model)
        items = repo.get_all()

        for item in items:
            val = getattr(item, attr_name)
            
            row = ctk.CTkFrame(self.items_listbox, fg_color="transparent")
            row.pack(fill="x", pady=2, padx=5)
            
            ctk.CTkLabel(row, text=val, anchor="w").pack(side="left", padx=10, expand=True, fill="x")
            
            # Botão para deletar o item
            ctk.CTkButton(
                row, text="Excluir", width=60, height=24,
                fg_color=vermelho_hexadecimal,
                command=lambda i=item.id, m=model: self.delete_mgmt_item(i, m)
            ).pack(side="right", padx=5)

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

############
    def update_loop(self):
        db = SessionLocal()

        try:
            config = db.query(Configuration).filter_by(id=1234).first()

            quantidade_de_trafegos_visiveis = (
                config.traffic_visible
                if config else general_settings.get("amount_of_visible_traffic")
            )

            pie_conf = graphs_configs.get("pie")
            barh_conf = graphs_configs.get("barh")
            line_conf = graphs_configs.get("line")

            logs = (
                db.query(TrafficLog)
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
                res_h = db.execute(text(barh_conf.get("query"))).fetchall()

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
                res_m = db.execute(text(pie_conf.get("query"))).fetchall()

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
            db.close()

        self.after(2000, self.update_loop)


async def start_proxy(core):
    opts = Options(listen_host=listen_host, listen_port=listen_port, mode=["regular"])
    master = DumpMaster(opts)

    try:
        with open(
            file="scripts/localization_injection.js",
            encoding="utf-8", mode="r"
        ) as script:
            content = script.read()
    except Exception as e:
        logger.info(f"Erro ao ler script JS: {e}")
        content = ""

    class SentinelAddon:
        def request(self, flow):
            core.process_flow(flow)
            flow.request.headers["User-Agent"] = fake_infos.get("header")
            flow.request.headers["X-Forwarded-For"] = fake_infos.get("ip")

            # POIS: Sem cookies, sem login
            # if "Cookie" in flow.request.headers:
            #     flow.request.headers["Cookie"] = "session_id=VALOR_FALSO_AQUI; " + flow.request.headers["Cookie"]

        
 
        def response(self, flow):
            core.process_response(flow)
            content_type = flow.response.headers.get("Content-Type", "")

            # Headers contra scripts
            flow.response.headers.pop("Content-Security-Policy", None)
            flow.response.headers.pop("X-Content-Security-Policy", None)
            flow.response.headers.pop("X-WebKit-CSP", None)

            if "text/html" in content_type:
                js_payload = f"<script>{content}</script>"
                html_original = flow.response.text
                
                if "</head>" in html_original.lower():
                    html_modificado = html_original.replace("</head>", js_payload + "</head>")
                    flow.response.text = html_modificado

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
    else:
        logger.info("Comando 'fuser' não disponível no Windows. O proxy pode não ser encerrado automaticamente.")

    loop.run_until_complete(start_proxy(core))



if __name__ == "__main__":
    login = ctk.CTk()
    login.title(auth_window.get("auth_title"))
    login.geometry(auth_window.get("window_size"))

    def auth():
        # if ent.get() == "admin":
        if "almondega":
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
