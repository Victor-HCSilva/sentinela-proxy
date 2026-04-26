


# 🛡️ Sentinela - Proxy & Network Monitor
`senha: admin`

**Sentinela** é uma aplicação desktop desenvolvida em Python para monitoramento, 
análise e auditoria de tráfego de rede (HTTP/HTTPS). Utilizando o poderoso núcleo do 
`mitmproxy` atuando como um *Man-In-The-Middle*, a ferramenta intercepta e registra dados de 
navegação, exibindo tudo em uma interface gráfica moderna e intuitiva construída com `CustomTkinter`.

Seja para fins de desenvolvimento, debugging de APIs ou auditoria de segurança, o
Sentinela oferece visibilidade sobre o que entra e sai da sua máquina.

### ✨ Principais Funcionalidades

*   📊 **Dashboard em Tempo Real:** Visualização do tráfego através de gráficos dinâmicos gerados com `Matplotlib` (Top Hosts acessados, Métodos HTTP mais utilizados e consumo atual de RAM).
*   🔍 **Inspetor de Conexões:** Histórico completo de requisições. Com um duplo-clique, é possível inspecionar detalhes cruciais como Headers, Payloads (Body), Tamanho e Métodos.
*   🛑 **Kill Switch (Bloqueio Rápido):** Um botão de emergência integrado que encerra instantaneamente navegadores ou processos específicos definidos nas configurações, utilizando a biblioteca `psutil`.
*   🗄️ **Registro Persistente:** Todo o tráfego interceptado é catalogado e armazenado em um banco de dados utilizando `SQLAlchemy`.
*   🌙 **Design Moderno:** Interface de usuário fluida em *Dark Mode*.

### 🛠️ Tecnologias Utilizadas

*   **[Python 3](https://www.python.org/):** Linguagem base.
*   **[Mitmproxy](https://mitmproxy.org/):** Motor principal para interceptação do tráfego HTTP/HTTPS.
*   **[CustomTkinter](https://github.com/TomSchimansky/CustomTkinter):** Criação da interface gráfica moderna e responsiva.
*   **[Matplotlib](https://matplotlib.org/):** Renderização dos gráficos de análise no painel (Dashboard).
*   **[SQLAlchemy](https://www.sqlalchemy.org/):** ORM para gerenciamento do banco de dados (armazenamento dos logs de tráfego).
*   **[Psutil](https://github.com/giampaolo/psutil):** Monitoramento de memória e encerramento de processos (Kill Switch).

- OBS: Testei unicamente em linux (Ubunto) e faltam varios ajustes