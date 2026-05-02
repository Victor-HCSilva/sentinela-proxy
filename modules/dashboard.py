from .base import Base
from sqlalchemy import text
from configs import graphs_configs, azul_hexadecimal, green_hexadecimal
from database import SessionLocal, TrafficLog # Assumindo que você tem este módulo
import psutil
import logging

logger = logging.getLogger(__name__)

class Dashboard(Base):
    """
    Dashboard
    """
    def __init__(self) -> None:
        super().__init__(self)
        second = 1000
        self.time_to_update = second * 2


    def update_loop(self):
        quantidade_de_trafegos_visiveis = self.amount_of_visible_traffic
        db = SessionLocal()
        try:
            pie_conf = graphs_configs.get("pie")
            barh_conf = graphs_configs.get("barh")
            line_conf = graphs_configs.get("line")

            logs = db.query(TrafficLog).order_by(TrafficLog.id.desc()).limit(quantidade_de_trafegos_visiveis).all()
            self.tree.delete(*self.tree.get_children())

            for log in logs:
                self.tree.insert("", "end", values=(log.id, log.timestamp.strftime("%H:%M:%S"), log.method, log.host, log.size))

            if self.dash_frame.winfo_ismapped():

                # Host Bar (Horizontal)
                self.ax_host.clear()
                res_h = db.execute(text(barh_conf.get("query"))).fetchall()
                if res_h:
                    self.ax_host.barh([r[0][:20] for r in res_h], [r[1] for r in res_h], color=azul_hexadecimal) # Usando a variável
                self.ax_host.set_title(barh_conf.get("title"), fontsize=barh_conf.get("font_size"), color=barh_conf.get("text_color"))

                # Pizza
                self.ax_meth.clear()
                res_m = db.execute(text(pie_conf.get("query"))).fetchall()

                if res_m:
                    self.ax_meth.pie([r[1] for r in res_m], labels=[r[0] for r in res_m], autopct='%1.1f%%', textprops={'color':pie_conf.get("text_color")}) # Usando a variável de cor
                self.ax_meth.set_title(pie_conf.get("title"), fontsize=pie_conf.get("font_size"), color=pie_conf.get("text_color"))

                # RAM Line
                self.ax_ram.clear()
                mem = psutil.virtual_memory().percent
                self.core.ram_history.append(mem)

                if len(self.core.ram_history) > 30:
                    self.core.ram_history.pop(0)

                self.ax_ram.plot(self.core.ram_history, color=green_hexadecimal, linewidth=2) # Usando a variável
                self.ax_ram.set_title(f"{line_conf.get("title")} {mem}%", fontsize=line_conf.get("font_size"), color=line_conf.get("text_color"))
                self.ax_ram.set_ylim(0, 100)

                self.fig.tight_layout()
                self.canvas.draw()

        except Exception as e:
            logger.error(f"Erro no loop de atualização: {e}") 
        finally:
            db.close()

        self.after(self.time_to_update, self.update_loop)