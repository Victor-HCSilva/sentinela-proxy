programs_name: list[str] = [
    "chrome", "firefox", "msedge", "brave"
]

listen_host, listen_port = '0.0.0.0', 8080

kill_proxy_command: list[str] = ["fuser", "-k", f"{listen_port}" + "/tcp"]

adds_domains: list[str] = [
    "doubleclick.net",
    # "googlesyndication.com",
    # "adservice.google.com",
    "facebook.com",
    # "analytics.google.com"
]

black_list: list[str] = []

white_list: list[str] = ["127.0.0.1", "localhost"]

block_keywords: list[str] = [
    # "ads", "banner", "tracker", "pixel"
]

db_config: dict[str: str] = {
    "db_name": "sentinela_v6_fixed.db",
    "engine_db_type": "sqlite:///",
}

