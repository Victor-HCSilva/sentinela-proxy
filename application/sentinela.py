import re
from configs import fake_infos

class SentinelAddon:
    def __init__(self, content: str, core, headers_to_pop):
        self.content = content
        self.core = core
        self.headers_to_pop = headers_to_pop

    def request(self, flow):
        if "/sentinela-ollama/" in flow.request.path:
            if flow.request.method == "OPTIONS":
                flow.response = http.Response.make(
                    200, b"", 
                    {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "*"
                    }
                )
                return

            # Extrai o caminho original (ex: /api/generate)
            original_path = flow.request.path.split("/sentinela-ollama/")[1]
            
            # Redireciona para o Ollama local
            flow.request.host = "127.0.0.1"
            flow.request.port = 11434
            flow.request.scheme = "http"
            flow.request.path = f"/{original_path}"
            
            # LIMPEZA CRÍTICA: Remove headers que denunciam que a chamada vem de outro site
            # Isso engana o Ollama para ele achar que é uma chamada local direta
            flow.request.headers.pop("Origin", None)
            flow.request.headers.pop("Referer", None)
            
            # Marca para adicionar headers de CORS na volta
            flow.metadata["sentinela_relay"] = True
            return

        self.core.process_flow(flow)
        
        # flow nunca é None no mitmproxy, podemos ir direto:
        flow.request.headers["User-Agent"] = fake_infos.get("header")
        flow.request.headers["X-Forwarded-For"] = fake_infos.get("ip")

    def response(self, flow):
        # Se for uma resposta do nosso relay, injeta os headers de CORS
        if flow.metadata.get("sentinela_relay"):
            flow.response.headers["Access-Control-Allow-Origin"] = "*"
            flow.response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            flow.response.headers["Access-Control-Allow-Headers"] = "*"
            return

        # 1. CRÍTICO: Descompacta o conteúdo antes de qualquer processamento
        try:
            flow.response.decode()
        except Exception:
            pass # Já está decodificado ou não é suportado

        self.core.process_response(flow)

        # 2. Remove headers de segurança que impedem a injeção ou causam upgrade forçado para HTTPS
        headers_to_remove = [
            "content-security-policy",
            "x-content-security-policy",
            "strict-transport-security",
            "content-security-policy-report-only"
        ]
        
        for h in self.headers_to_pop:
            flow.response.headers.pop(h, None)
            
        for h in headers_to_remove:
            flow.response.headers.pop(h, None)

        content_type = flow.response.headers.get("Content-Type", "").lower()
        
        # 3. Só prossegue se for HTML real
        if "text/html" in content_type and flow.response.text:
            
            debug_js = "\nconsole.log('🛡️ Sentinel: Scripts injetados com sucesso');\n"
            js_payload = f"<script>{debug_js}{self.content}</script>"
            
            if "</body>" in flow.response.text.lower():
                flow.response.text = re.sub(
                    r"</body>", 
                    f"{js_payload}</body>", 
                    flow.response.text, 
                    flags=re.IGNORECASE, 
                    count=1
                )
            elif "</head>" in flow.response.text.lower():
                flow.response.text = re.sub(
                    r"</head>", 
                    f"{js_payload}</head>", 
                    flow.response.text, 
                    flags=re.IGNORECASE, 
                    count=1
                )
            else:
                flow.response.text += js_payload
