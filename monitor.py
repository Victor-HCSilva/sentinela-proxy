from mitmproxy import http
import time
import os
from dotenv import load_dotenv

load_dotenv()

TIME_WINDOW: int = os.getenv("TIME_WINDOW", default=10)
REQUEST_THRESHOLD: int = os.getenv("REQUEST_THRESHOLD", default=10)
SIZE_MULTIPLIER_ALERT: int = os.getenv("SIZE_MULTIPLIER_ALERT", default=2)

# ===== ESTADO =====
request_log = {}
size_baseline = {}

def request(flow: http.HTTPFlow):
    host = flow.request.host
    now = time.time()

    # Inicializa estruturas
    if host not in request_log:
        request_log[host] = []

    # Log de tempo
    request_log[host].append(now)

    # Limpa janela antiga
    request_log[host] = [t for t in request_log[host] if now - t < TIME_WINDOW]

    # 🚨 DETECÇÃO 1: frequência alta
    if len(request_log[host]) > REQUEST_THRESHOLD:
        alert(f"ALTA FREQUÊNCIA: {host} → {len(request_log[host])} reqs")

    # 🚨 DETECÇÃO 2: padrões suspeitos
    url = flow.request.pretty_url
    suspicious_patterns = ["track", "collect", "fingerprint"]

    for pattern in suspicious_patterns:
        if pattern in url:
            alert(f"PADRÃO SUSPEITO: {url}")


def response(flow: http.HTTPFlow):
    host = flow.request.host

    size = len(flow.response.content or b"")

    # baseline simples
    if host not in size_baseline:
        size_baseline[host] = size
        return

    baseline = size_baseline[host]

    # 🚨 DETECÇÃO 3: tráfego anormal (2x maior)
    if baseline > 0 and size > baseline * SIZE_MULTIPLIER_ALERT:
        alert(f"TRÁFEGO ANORMAL: {host} → {size} bytes (baseline {baseline})")

    # atualiza média simples
    size_baseline[host] = int((baseline + size) / 2)


# ===== ALERTA =====
def alert(msg):
    print(f"[ALERTA] {msg}")

