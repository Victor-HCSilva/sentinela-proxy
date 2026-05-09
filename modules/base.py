import customtkinter as ctk
from configs import app_config


class Base(ctk.CTk):
    def __init__(self, core) -> None:
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
