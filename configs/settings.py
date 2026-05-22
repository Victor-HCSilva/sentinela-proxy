#  Colors
white = "white"

azul_hexadecimal = "#1f538d"

vermelho_hexadecimal = "#7b241c"

green_hexadecimal = "#00ff00"

gray_headecimal = "#333333"

gray = "gray25"


# interface
app_config = {
    "app_name": "SENTINELA NETWORK GUARDIAN",
    "logo_name": "SENTINELA👁️",
    "window_size": "1100x850",
}

ctk_button_labels = {
    "dashboard": "Dashboard",
    "monitor": "Monitor",
    "kill": "Kill Browsers",
    "login": "Enter",
    "settings": "Settings",
    "settings_confirmation": "Save",
}

auth_window = {"auth_title": "Sentinela Auth", "window_size": "300x200"}


auth_labels = {
    "content_title": "ACESSO RESTRITO",
    "font": ("Arial", 14, "bold"),
    "confirm_button": "Entrar",
    "placeholder_text": "Senha",
    "incorret_password_message": {
        "context_title": "Erro",
        "message": "Senha incorreta",
    },
}


graphs_configs = {
    "pie": {
        "title": "MÉTODOS HTTP",
        "font_size": 10,
        "text_color": white,
        "query": "SELECT method, COUNT(id) FROM traffic_logs GROUP BY method",
    },
    "barh": {
        "title": "TOP 5 DESTINOS",
        "font_size": 10,
        "text_color": white,
        "query": "SELECT host, COUNT(id) as c FROM traffic_logs GROUP BY host ORDER BY c DESC LIMIT 5",
    },
    "line": {
        "title": "USO DE MEMÓRIA:",
        "font_size": 10,
        "text_color": white,
        "query": "",
    },
}


kill_command_message = {
    "content_title": "Firewall Active",
    "message": "Protocolo de encerramento concluído.",
}


inspector_window = {
    "inspector_title": "Packet Inspector:",
    "inspector_detail_size": "700x500",
    "box": {
        # "text_box": 23,
        "width": 680,
        "height": 480,
        "font": ("Consolas", 12),
    },
}


table_labels = {
    "id": "ID",
    "hora": "HORA",
    "med": "MÉD",
    "host": "HOST",
    "size": "BYTES",
}

table_headers = [v for _, v in table_labels.items()]

table = {
    "id": {"heading": {"text": table_labels.get("id")}, "column": {"width": 50}},
    "hora": {"heading": {"text": table_labels.get("hora")}, "column": {"width": 80}},
    "med": {"heading": {"text": table_labels.get("med")}, "column": {"width": 60}},
    "host": {"heading": {"text": "DOMÍNIO/URL"}, "column": {"width": 450}},
    "size": {"heading": {"text": table_labels.get("size")}, "column": {"width": 80}},
}

# porta do host
listen_host = "0.0.0.0"
listen_port = 8080

# perfil falso
fake_infos = {
    "header": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",
    "ip": "198.163.111.1",
}

# tipo de conteudo
content_type = {
    "json": "application/json",
    "img": "image/png",
    "html": "text/html",
    "js": "text/javascript",
}

# configuraçõe gerais
general_settings = {
    "theme": "dark",  # dark, system light TODO: tabela de configurações
    "programs_name": ["chrome", "firefox", "msedge", "brave"],
    "kill_proxy_command": ["fuser", "-k", f"{listen_port}" + "/tcp"],
}
