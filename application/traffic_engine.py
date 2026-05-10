from mitmproxy import http
from database import (
    ConfigSessionLocal,
    AddDomain,
    BlockKeyWord,
    WhiteList,
    ExcludeHeader,
)
from sqlalchemy.orm import joinedload
import logging

logger = logging.getLogger(__name__)


class TrafficFilterEngine:
    """Auxliar para ações de bloqueio"""
    def __init__(self):
        # caches
        self.ad_domains = set()
        self.block_keywords = set()
        self.global_exclude_headers = set()

        # regras específicas por URL
        self.url_header_rules = {}      # {host: set(headers)}
        self.url_keyword_rules = {}     # {host: set(keywords)}

        self.load_rules()

    # =========================
    # LOAD RULES DO BANCO
    # =========================
    def load_rules(self):
        db = ConfigSessionLocal()

        try:

            ads = (
                db.query(AddDomain)
                .options(joinedload(AddDomain.url))
                .all()
            )

            self.ad_domains = {
                item.url.url for item in ads if item.url
            }

            keywords = (
                db.query(BlockKeyWord)
                .filter_by(is_active=True)
                .all()
            )

            self.block_keywords = {
                k.word.lower()
                for k in keywords
            }

            headers = db.query(ExcludeHeader).all()

            self.global_exclude_headers = {
                h.field_name.lower()
                for h in headers
            }

            white = (
                db.query(WhiteList)
                .options(
                    joinedload(WhiteList.url),
                    joinedload(WhiteList.exclude_header),
                    joinedload(WhiteList.block_keyword)
                )
                .all()
            )

            self.url_header_rules = {}
            self.url_keyword_rules = {}

            for item in white:

                if not item.url:
                    continue

                host = item.url.url

                if item.exclude_header:
                    self.url_header_rules.setdefault(
                        host,
                        set()
                    ).add(
                        item.exclude_header.field_name.lower()
                    )

                if item.block_keyword:
                    self.url_keyword_rules.setdefault(
                        host,
                        set()
                    ).add(
                        item.block_keyword.word.lower()
                    )

        except Exception as e:
            logger.error(f"Erro ao carregar regras: {e}")

        finally:
            db.close()

    # =========================
    # REQUEST
    # =========================
    def handle_request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        url = flow.request.pretty_url.lower()

        # ---------------------
        # BLOQUEIO por ads
        # ---------------------
        if any(domain in host for domain in self.ad_domains):
            return self.block(flow, "Ad domain")

        # ---------------------
        # KEYWORDS (global + por URL)
        # ---------------------
        keywords = set(self.block_keywords)

        if host in self.url_keyword_rules:
            keywords |= self.url_keyword_rules[host]

        if any(k in url for k in keywords):
            return self.block(flow, "Keyword match")

        # ---------------------
        # REMOÇÃO DE HEADERS
        # ---------------------
        headers_to_remove = set(self.global_exclude_headers)

        if host in self.url_header_rules:
            headers_to_remove |= self.url_header_rules[host]

        for header in headers_to_remove:
            if flow is None:
                continue
            flow.request.headers.pop(header, None)

    # =========================
    # RESPONSE
    # =========================
    def handle_response(self, flow: http.HTTPFlow):
        content_type = flow.response.headers.get("content-type", "").lower()

        # keywords globais
        keywords = set(self.block_keywords)

        host = flow.request.pretty_host

        if host in self.url_keyword_rules:
            keywords |= self.url_keyword_rules[host]

        if "text/html" in content_type:
            try:
                text = flow.response.text

                for k in keywords:
                    text = text.replace(k, "")

                flow.response.text = text

            except Exception as e:
                logger.error(f"Erro ao processar HTML: {e}")

        if "application/json" in content_type:
            if "ads" in flow.request.pretty_url.lower():
                flow.response.text = "{}"

    # =========================
    # BLOQUEIO
    # =========================
    def block(self, flow, reason="Blocked"):
        flow.response = http.Response.make(
            403,
            f"Blocked: {reason}".encode(),
            {"Content-Type": "text/plain"},
        )

    # =========================
    # RELOAD
    # =========================
    def reload(self):
        self.load_rules()

    def __str__(self):
        return "Class - TrafficFilterEngine"

