import re
from configs import fake_infos


class SentinelAddon:
    def __init__(self, content: str, core, headers_to_pop):
        self.content = content
        self.core = core
        self.headers_to_pop = headers_to_pop

    def request(self, flow):
        self.core.process_flow(flow)
        if flow is not None:
            flow.request.headers["User-Agent"] = fake_infos.get("header")
            flow.request.headers["X-Forwarded-For"] = fake_infos.get("ip")

    def response(self, flow):
        self.core.process_response(flow)

        # Agora o self.headers_to_pop existe e foi carregado no init
        for header in self.headers_to_pop:
            if flow is None:
                continue
            flow.response.headers.pop(header, None)

        content_type = flow.response.headers.get("Content-Type", "")
        if "text/html" in content_type and flow.response.content:
            
            js_payload = f"<script>\n{self.content}\n</script>\n</head>"
            
            # re.sub com re.IGNORECASE acha a tag mesmo que seja </HEAD> ou </head>
            flow.response.text = re.sub(
                r'</head>', 
                js_payload, 
                flow.response.text, 
                flags=re.IGNORECASE
            )
