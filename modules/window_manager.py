import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinter import ttk
from configs import (
    azul_hexadecimal,
    table, general_settings,
    green_hexadecimal
)
import matplotlib as plt


class WM:
    """Gerenciador da janela em foco"""
    def setup_main_frames(self):
        self.dash_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        self.fig, (self.ax_host, self.ax_meth, self.ax_ram) = plt.subplots(3, 1, figsize=(6, 12))
        # self.fig.patch.set_facecolor('#1a1a1a')
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
            columns=list(table.keys()),
            show='headings'
        )

        for column_id, column_data in table.items():
            heading_text = column_data["heading"]["text"]
            column_config = column_data["column"]

            self.tree.heading(column_id, text=heading_text)
            self.tree.column(column_id, **column_config)

        self.tree.pack(fill="both", expand=True, padx=20, pady=10)
        self.tree.bind("<Double-1>", self.open_inspection)

        self.settings_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        
        ctk.CTkLabel(
            self.settings_frame, 
            text="Configurações do Sistema",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        options_frame = ctk.CTkFrame(self.settings_frame, fg_color="transparent")
        options_frame.pack(pady=20, padx=40, fill="both", expand=True)
        
        ctk.CTkLabel(options_frame, text="Tema Escuro:").grid(row=0, column=0, pady=10, sticky="w")
        theme_switch = ctk.CTkSwitch(
            options_frame, 
            text="Ativado" if ctk.get_appearance_mode() == "Dark" else "Desativado",
            command=lambda: self.toggle_theme(theme_switch)
        )
        theme_switch.grid(row=0, column=1, pady=10, padx=20)
        theme_switch.select() if ctk.get_appearance_mode() == "Dark" else theme_switch.deselect()
        
        ctk.CTkLabel(options_frame, text="Tráfego visível:").grid(row=1, column=0, pady=10, sticky="w")
        traffic_entry = ctk.CTkEntry(options_frame, placeholder_text="Quantidade de registros")
        traffic_entry.grid(row=1, column=1, pady=10, padx=20)
        traffic_entry.insert(0, str(general_settings.get("amount_of_visible_traffic", 100)))
        
        ctk.CTkButton(
            options_frame,
            text="Salvar Configurações",
            command=lambda: self.save_settings(traffic_entry.get(), theme_switch.get()),
            fg_color=green_hexadecimal
        ).grid(row=2, column=0, columnspan=2, pady=30)
