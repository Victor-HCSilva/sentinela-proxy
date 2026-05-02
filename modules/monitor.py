from .config import Base
from database import SessionLocal, TrafficLog
from configs import inspector_window
import customtkinter as ctk


class MonitorInspector(Base):
    def __init__(self):
        super().__init__(self)


    
    def open_inspection(self, event):
        """
        Detalhamento de requisição (inspeção)
        """
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

        
            data = f"DOMÍNIO: {log.host}\nMÉTODO: {log.method}\nTAMANHO: {log.size} bytes\n"
            data += f"\n--- HEADERS ---\n{log.headers}\n"
            data += f"\n--- PAYLOAD (BODY) ---\n{log.payload if log.payload else '[Vazio]'}"
            txt.insert("0.0", data)


