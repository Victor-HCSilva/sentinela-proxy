import os

# colors
Vermelho= "\033[31m"
Verde= "\033[32m"
Amarelo= "\033[33m"
Azul= "\033[34m"
Roxo= "\033[35m"
Ciano= "\033[36m"
Branco= "\033[37m"


def alert(msg: str):
    os.system(msg)


if __name__ == "__main__":
    alert('Olá mundo')
