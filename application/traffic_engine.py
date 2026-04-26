from mitmproxy import http
from configs import general_settings 
import logging
import os


logging = logging.getLogger()

class TrafficFilterEngine:
    def __init__(self):
        self.truted_urls = []
        self.ad_domains = general_settings.get("adds_domains")
        self.block_keywords = general_settings.get("block_keywords")

    def handle_request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        url = flow.request.pretty_url

        if any(domain in host for domain in self.ad_domains):
            return self.block(flow, "Ad domain")
            
        if any(k in url.lower() for k in self.block_keywords):
            return self.block(flow, "Keyword match")
    
        for _ in general_settings.get("headers_to_exclude"):
            flow.request.headers.pop("referer", None)

    def handle_response(self, flow: http.HTTPFlow):
        content_type = flow.response.headers.get("content-type", "")

        if "text/html" in content_type:
            try:
                text = flow.response.text

                for k in self.block_keywords:
                    text = text.replace(k, "")

                flow.response.text = text
            except Exception as e:  
                logging.info(f"Erro ocorrido: {e}")
                os.system(f"Erro inesperado em {self.__str__()} check logs")

        if "application/json" in content_type:
            if "ads" in flow.request.pretty_url:
                flow.response.text = "{}"


    def block(self, flow, reason="Blocked"):
        flow.response = http.Response.make(
            403,
            f"Blocked: {reason}".encode(),
            {"Content-Type": "text/plain"}
        )

    def __str__(self):
        return "Class - TrafficFilterEngine"