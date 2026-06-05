from tkinter import messagebox

import customtkinter as ctk

from configs import green_hexadecimal
from database import (
    AddDomain,
    BlackList,
    BlockKeyWord,
    ConfigSessionLocal,
    ExcludeHeader,
    Url,
    WhiteList,
)


class ConfigData(ctk.CTkFrame):
    """
    Procura informações no banco de dados: BLACKLIST, WHITELIST, URLs
    """

    def __init__(self, master, controller=None):
        super().__init__(master, corner_radius=1, fg_color="transparent")
        self.controller = controller
        self.setup_ui()

    def refresh_mgmt_list(self, _=None) -> None:
        # 1. Limpa os itens antigos da tela para não duplicar
        for widget in self.items_listbox.winfo_children():
            widget.destroy()

        category = self.category_var.get()
        db = ConfigSessionLocal()

        try:
            items = []  # Vai guardar tuplas no formato: (id_do_item, texto_para_exibir)

            if category == "URLs":
                results = db.query(Url).all()
                items = [(r.id, r.url) for r in results]

            elif category == "Palavras Bloqueadas":
                results = db.query(BlockKeyWord).all()
                items = [(r.id, r.word) for r in results]

            elif category == "Headers Excluídos":
                results = db.query(ExcludeHeader).all()
                items = [(r.id, r.field_name) for r in results]

            # Para Blacklist, Whitelist e Ads, precisamos fazer um JOIN com a tabela Url
            # pois essas tabelas salvam apenas o 'url_id'
            elif category == "Blacklist":
                results = db.query(BlackList, Url).join(Url, BlackList.url_id == Url.id).all()
                items = [(bl.id, url.url) for bl, url in results]

            elif category == "Whitelist":
                results = db.query(WhiteList, Url).join(Url, WhiteList.url_id == Url.id).all()
                items = [(wl.id, url.url) for wl, url in results]

            elif category == "Domínios de Anúncio":
                results = db.query(AddDomain, Url).join(Url, AddDomain.url_id == Url.id).all()
                items = [(ad.id, url.url) for ad, url in results]

            # 2. Desenha os itens na tela
            for item_id, item_text in items:
                # Cria uma "linha" para cada item
                row_frame = ctk.CTkFrame(self.items_listbox, fg_color="transparent")
                row_frame.pack(fill="x", pady=2)

                lbl = ctk.CTkLabel(row_frame, text=item_text, anchor="w")
                lbl.pack(side="left", fill="x", expand=True, padx=(5, 10))

                # Botão de deletar o item (chama a função delete_item que criaremos abaixo)
                btn_del = ctk.CTkButton(
                    row_frame,
                    text="Excluir",
                    width=60,
                    fg_color="#c0392b",  # Vermelho
                    hover_color="#922b21",
                    command=lambda i=item_id, c=category: self.delete_item(i, c),
                )
                btn_del.pack(side="right")

        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao carregar lista:\n{e}")
        finally:
            db.close()

    def setup_ui(self):
        self.settings_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.settings_frame.pack(fill="both", expand=True)

        """Cria a interface para gerenciar listas (Whitelist, Blacklist, Words)"""
        self.mgmt_frame = ctk.CTkFrame(self.settings_frame)
        self.mgmt_frame.pack(pady=10, padx=20, fill="both", expand=True)

        ctk.CTkLabel(
            self.mgmt_frame,
            text="Gerenciamento de Regras",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(pady=(15, 5), anchor="w", padx=20)

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

        self.new_entry = ctk.CTkEntry(action_bar, placeholder_text="Digite o novo valor aqui...")
        self.new_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        add_btn = ctk.CTkButton(
            action_bar,
            text="Adicionar",
            fg_color=green_hexadecimal,
            command=self.add_to_list,
            width=100,
        )
        add_btn.pack(side="right")

        # NOTE: Ordem importa
        self.items_listbox = ctk.CTkScrollableFrame(self.mgmt_frame)
        self.items_listbox.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.refresh_mgmt_list()

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
            messagebox.showinfo("Sucesso", "Valor adicionado com sucesso!")

        except Exception as e:
            db.rollback()
            messagebox.showerror("Erro", f"Não foi possível adicionar:\n{e}")

        finally:
            db.close()

    def delete_item(self, item_id, category):
        # Confirmação antes de deletar
        if not messagebox.askyesno("Confirmar", "Tem certeza que deseja excluir este item?"):
            return

        db = ConfigSessionLocal()
        try:
            if category == "URLs":
                db.query(Url).filter_by(id=item_id).delete()
            elif category == "Palavras Bloqueadas":
                db.query(BlockKeyWord).filter_by(id=item_id).delete()
            elif category == "Headers Excluídos":
                db.query(ExcludeHeader).filter_by(id=item_id).delete()
            elif category == "Blacklist":
                db.query(BlackList).filter_by(id=item_id).delete()
            elif category == "Whitelist":
                db.query(WhiteList).filter_by(id=item_id).delete()
            elif category == "Domínios de Anúncio":
                db.query(AddDomain).filter_by(id=item_id).delete()

            db.commit()
            self.refresh_mgmt_list()  # Atualiza a lista na tela

            # Recarrega as configurações no Core do proxy
            if self.controller and hasattr(self.controller, "core"):
                self.controller.core.load_configs()

        except Exception as e:
            db.rollback()
            messagebox.showerror("Erro", f"Erro ao excluir:\n{e}")
        finally:
            db.close()
