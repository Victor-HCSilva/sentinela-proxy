from mitmproxy import http
from sqlalchemy import select
from configs import fake_infos
from database import ExcludeHeader, SessionLocal

class SentinelAddon:
    def __init__(self, content: str, core, headers_to_pop):
        self.content = content
        self.core = core
        self.headers_to_pop = headers_to_pop

    def request(self, flow):
        self.core.process_flow(flow)
        flow.request.headers["User-Agent"] = fake_infos.get("header")
        flow.request.headers["X-Forwarded-For"] = fake_infos.get("ip")

    def response(self, flow):
        self.core.process_response(flow)
        
        # Agora o self.headers_to_pop existe e foi carregado no init
        for header in self.headers_to_pop:
            flow.response.headers.pop(header, None)

        content_type = flow.response.headers.get("Content-Type", "")
        if "text/html" in content_type:
            js_payload = f"<script>{self.content}</script>"
            if "</head>" in flow.response.text.lower():
                flow.response.text = flow.response.text.replace("</head>", js_payload + "</head>")