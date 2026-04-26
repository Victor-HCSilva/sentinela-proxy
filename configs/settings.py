# TODO: transformar em JSON

white = 'white'

azul_hexadecimal = "#1f538d"


vermelho_hexadecimal = "#7b241c"


green_hexadecimal = "#00ff00"


gray_headecimal = "#333333"


gray = "gray25"


app_config = {
    "app_name": "SENTINELA NETWORK GUARDIAN Pro", 
    "logo_name": "SENTINELA",
    "window_size": "1100x850",
}


ctk_button_labels = {
    "dashboard":"Dashboard",
    "monitor": "Monitor Real Time",
    "kill": "FIREWALL KILL",
    "login": "ENTRAR",
}

auth_window = {
    "auth_title" : "Sentinela Auth",
    "window_size": "300x200"
}


auth_labels = {
    "content_title": "ACESSO RESTRITO",
    "font": ("Arial", 14, "bold"),
    "confirm_button": "Entrar",
    "placeholder_text": "Senha",
    "incorret_password_message": 
        {
            "context_title": "Erro",
            "message": "Senha incorreta"
        }, 
}


graphs_configs = {
    "pie": 
    {
        "title": "MÉTODOS HTTP",
        "font_size": 10,
        "text_color": white,
        "query": "SELECT method, COUNT(id) FROM traffic_logs GROUP BY method"
    },
    "barh": 
    {
        "title": "TOP 5 DESTINOS",
        "font_size": 10,
        "text_color": white,
        # TODO: Subistituir por ORM, para menos hard_code
        "query": "SELECT host, COUNT(id) as c FROM traffic_logs GROUP BY host ORDER BY c DESC LIMIT 5"
    },
    "line": 
    {
        "title": "USO DE MEMÓRIA:",
        "font_size": 10,
        "text_color": white,
        "query": "", 
    },
}
 

kill_command_message = {
    "content_title":"Firewall Active",
    "message":"Protocolo de encerramento concluído.",
}


inspector_window = {
    "inspector_title":"Packet Inspector:",
    "inspector_detail_size": "700x500",
    "box": {
        # "text_box": 23,
        "width": 680,
        "height": 480, 
        "font":("Consolas", 12),
    }
}


table_labels = {
    "id": "ID",
    "hora": "HORA",
    "med": "MÉD",
    "host": "HOST",
    "size": "BYTES",
}

table_headers = ([v for _, v in table_labels.items()]) # Corrigido para iterar sobre itens

table = {
    "id": {
        "heading": {
            "text": table_labels.get('id')
        },
        "column": {
            "width": 50
        }
    },
    "hora": {
        "heading": {
            "text": table_labels.get('hora')
        },
        "column": {
            "width": 80
        }
    },
    "med": {
        "heading": {
            "text": table_labels.get('med')
        },
        "column": {
            "width": 60
        }
    },
    "host": {
        "heading": {
            "text": "DOMÍNIO/URL" 
        },
        "column": {
            "width": 450
        }
    },
    "size": {
        "heading": {
            "text": table_labels.get('size')
        },
        "column": {
            "width": 80
        }
    },
}

listen_host= '0.0.0.0'

listen_port=  8080

general_settings = {
    "theme": "system", # dark, system light
    "db_config": 
    {
        "db_name": "sentinela_v6_fixed.db",
        "engine_db_type": "sqlite:///",
    },
    "programs_name":  
    [
        "chrome",
        "firefox",
        "msedge",
        "brave"
    ],
    "kill_proxy_command": 
    [
        "fuser", 
        "-k",
        f"{listen_port}" + "/tcp"
    ],
    "adds_domains": 
    {
        "doubleclick.net",
        "facebook.com",
    },
    "black_list": [],
    "white_list": [
        "127.0.0.1", 
        "localhost"
    ],
    "block_keywords": [], # ["ads", "banner", "tracker", "pixel"]
    "headers_to_exclude": 
    [
        "cookie",
        "referer"
    ],
    "amount_of_visible_traffic": 32,
}