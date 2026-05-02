import customtkinter as ctk
from configs import (
    general_settings, green_hexadecimal,
    amount_of_visible_traffic, ctk_button_labels
)
from tkinter import messagebox


class Settings(ctk):
    amount_of_visible_traffic = amount_of_visible_traffic
    amount_of_visible_traffic_limit = 55

    def toggle_theme(self, switch: str):
        options = [
            "dark",
            "light",
            "system"
        ]
        for style in options:
            if style == switch.lower().strip():
                ctk.set_appearance_mode(switch.capitalize())
                switch.configure(text="Ativado")    


    def settings(self):
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
            text=ctk_button_labels.get("settings_confirmation"),
            command=lambda: self.save_settings(traffic_entry.get(), theme_switch.get()),
            fg_color=green_hexadecimal
        ).grid(row=2, column=0, columnspan=2, pady=30)

    def save_settings(self, traffic_amount, theme_state):
        """Salva as configurações"""
        try:
            self.amount_of_visible_traffic = (
                int(traffic_amount) 
                if traffic_amount < amount_of_visible_traffic 
                else amount_of_visible_traffic
            )
            messagebox.showinfo("Sucesso", "Configurações salvas! Reinicie para aplicar todas as alterações.")
        except ValueError:
            messagebox.showerror("Erro", "Digite um número válido para quantidade de tráfego")
