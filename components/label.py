
import customtkinter as ctk
from typing import Any

class Label:
    """
    Cria botões formatados conforme o sistema precisa
    """
    def __init__(
        self, 
        obj: Any, 
        identifier: str,
        label="label",
        font: dict[str:int, str:str]= {"size": 24, "weight": "bold"},
    ):
        self.identifier = identifier
        return ctk.CTkLabel(
            obj, 
            text=label,
            font=ctk.CTkFont(**font)
        )
        
    def identifier(self) -> str:
        """Identificador único"""
        return self.identifier if self.identifier else "btn"

    
def main():
    print("Olá mundo")

if __name__ == "__main__":
    ...