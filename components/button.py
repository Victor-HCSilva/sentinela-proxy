import customtkinter as ctk

class Btn:
    def __init__(self, func, obj, identifier, args=None, label="Button", fg_color="#1f538d", **kwargs):
        self.identifier = identifier
        self.func = func
        self.args = args or ()
        self.button = ctk.CTkButton(
            obj, text=label, fg_color=fg_color, command=self._on_click, **kwargs
        )

    def _on_click(self):
        self.func(*self.args)

    def pack(self, **kwargs):
        self.button.pack(**kwargs)

    def set_color(self, color: str):
        self.button.configure(fg_color=color)
    
    def is_visible(self, visible: bool):
        self.button.show() if visible else self.button.hide()


# --- Uso ---
def main(context):
    print("Olá mundo ", context)

def mudar_de_cor(btn, color):  btn.set_color(color)


class Window:
    def __init__(self, width=400, height=300, title="New Window"):
        self.window = ctk.CTk()
        self.window.geometry(f"{width}x{height}")
        self.window.title(title)
        
        # Dicionário para armazenar suas telas (Frames)
        self.frames = {}
        
        # Criando as telas
        self.frames["tela1"] = ctk.CTkFrame(self.window)
        self.frames["tela2"] = ctk.CTkFrame(self.window)

    def mostrar_tela(self, nome_tela):
        # 1. Esconde todas as telas
        for frame in self.frames.values():
            frame.pack_forget()
        
        # 2. Mostra apenas a tela solicitada
        if nome_tela in self.frames:
            self.frames[nome_tela].pack(fill="both", expand=True)

    def start(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = Window()

    # --- Conteúdo da Tela 1 ---
    btn_ir_para_2 = ctk.CTkButton(app.frames["tela1"], text="Ir para Tela 2", 
                                  command=lambda: app.mostrar_tela("tela2"))
    btn_ir_para_2.pack(pady=20)

    # --- Conteúdo da Tela 2 ---
    btn_voltar_para_1 = ctk.CTkButton(app.frames["tela2"], text="Voltar para Tela 1", 
                                      command=lambda: app.mostrar_tela("tela1"))
    btn_voltar_para_1.pack(pady=20)

    # Inicia mostrando a tela 1
    app.mostrar_tela("tela1")
    
    app.start()