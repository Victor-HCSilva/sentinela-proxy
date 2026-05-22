import customtkinter as ctk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master, controller=None):
        super().__init__(master, corner_radius=0, fg_color="transparent")
        self.controller = controller

        self.fig, (self.ax_host, self.ax_meth, self.ax_ram) = plt.subplots(3, 1, figsize=(6, 12))
        self.fig.patch.set_facecolor("#1a1a1a")

        for ax in [self.ax_host, self.ax_meth, self.ax_ram]:
            ax.set_facecolor("#1a1a1a")
            ax.tick_params(colors="white")
            ax.title.set_color("white")

        self.ax_ram.tick_params(axis="both", labelsize=8)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)
