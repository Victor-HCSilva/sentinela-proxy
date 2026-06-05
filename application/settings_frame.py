import customtkinter as ctk

from configs.settings import green_hexadecimal  # TODO: colors.py
from database import ConfigSessionLocal, Configuration


class SettingsFrame(ctk.CTkFrame):
    def __init__(self, master, controller=None):
        # Inicia o frame invisível que vai segurar os itens
        super().__init__(master, corner_radius=0, fg_color="transparent")

        self.controller = controller
        self.setup_ui()
        self.setup_management_tab()
        self.refresh_mgmt_list()

    def setup_ui(self):
        # 1. TÍTULO
        # ctk.CTkLabel(
        #     self, # <- Note que é "self". Ele é colado na própria classe!
        #     text="Configurações do Sistema",
        #     font=ctk.CTkFont(size=24, weight="bold"),
        # ).pack(pady=(20, 10))

        # 2. FRAME DE OPÇÕES GERAIS (Topo)
        options_frame = ctk.CTkFrame(self)
        options_frame.pack(pady=10, padx=20, fill="x")

        # ===== CARREGAR CONFIG DO BANCO =====
        db = ConfigSessionLocal()
        _ = db.query(Configuration).filter_by(id=1234).first()
        db.close()

        # Mock provisório para testar a UI
        traffic_value = 100
        theme_value = "Dark"
        theme_value = "Light"

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

        if theme_value == "Light":
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

    def setup_management_tab(self):
        pass  # Implementar depois

    def refresh_mgmt_list(self):
        pass  # Implementar depois

    def _toggle_theme_state(self):
        pass  # Implementar depois

    def apply_settings(self):
        pass  # Implementar depois
