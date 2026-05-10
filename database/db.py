import enum
import os
import tempfile
from datetime import datetime, timezone
import logging

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Text as SQLText,
    Enum as SQLEnum,
    ForeignKey,
    Boolean,
)

from sqlalchemy.orm import (
    sessionmaker,
    declarative_base,
    relationship,
)

# =====================
# LOGGER
# =====================
logger = logging.getLogger(__name__)

# =====================
# PATHS
# =====================

# Banco TEMPORÁRIO (/tmp)
temp_db_name = "sentinela_traffic.db"
temp_db_path = os.path.join(
    tempfile.gettempdir(),
    temp_db_name
)

# Banco PERSISTENTE (configurações)
config_db_path = os.path.join(
    os.getcwd(),
    "config.db"
)

TEMP_DB_URL = f"sqlite:///{temp_db_path}"
CONFIG_DB_URL = f"sqlite:///{config_db_path}"

# =====================
# ENGINES
# =====================

# Banco temporário
traffic_engine = create_engine(
    TEMP_DB_URL,
    connect_args={"check_same_thread": False},
)

# Banco persistente
config_engine = create_engine(
    CONFIG_DB_URL,
    connect_args={"check_same_thread": False},
)

# =====================
# SESSIONS
# =====================

TrafficSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=traffic_engine,
)

ConfigSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=config_engine,
)

# =====================
# BASES
# =====================

TrafficBase = declarative_base()
ConfigBase = declarative_base()

# =====================
# ENUMS
# =====================

class Theme(enum.Enum):
    DARK = "Dark"
    LIGHT = "Light"
    SYSTEM = "System"


# =====================
# HELPERS
# =====================

def now_utc():
    return datetime.now(timezone.utc)


# =========================================================
# ================= TEMP DATABASE =========================
# =========================================================

class TrafficLog(TrafficBase):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True)

    timestamp = Column(
        DateTime,
        default=now_utc
    )

    host = Column(String)
    method = Column(String)
    size = Column(Integer)

    headers = Column(SQLText)
    payload = Column(SQLText)


# =========================================================
# ============== CONFIG DATABASE ==========================
# =========================================================

class Configuration(ConfigBase):
    __tablename__ = "configs"

    id = Column(Integer, primary_key=True)

    timestamp = Column(
        DateTime,
        default=now_utc
    )

    traffic_visible = Column(Integer)

    theme = Column(
        SQLEnum(
            Theme,
            native_enum=False
        ),
        default=Theme.DARK,
        nullable=False,
    )


class Url(ConfigBase):
    __tablename__ = "urls"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    url = Column(
        String,
        unique=True,
        nullable=False
    )


class AddDomain(ConfigBase):
    __tablename__ = "add_domains"

    id = Column(Integer, primary_key=True)

    timestamp = Column(
        DateTime,
        default=now_utc
    )

    url_id = Column(
        Integer,
        ForeignKey("urls.id")
    )

    url = relationship(
        "Url",
        lazy="joined"
    )

    is_active = Column(
        Boolean,
        default=True
    )


class BlockKeyWord(ConfigBase):
    __tablename__ = "block_key_words"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    timestamp = Column(
        DateTime,
        default=now_utc
    )

    word = Column(
        String,
        unique=True,
        nullable=False
    )

    is_active = Column(
        Boolean,
        default=True
    )


class BlackList(ConfigBase):
    __tablename__ = "black_list"

    id = Column(Integer, primary_key=True)

    timestamp = Column(
        DateTime,
        default=now_utc
    )

    url_id = Column(
        Integer,
        ForeignKey("urls.id")
    )

    url = relationship(
        "Url",
        lazy="joined"
    )


class ExcludeHeader(ConfigBase):
    __tablename__ = "exclude_headers"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    timestamp = Column(
        DateTime,
        default=now_utc
    )

    field_name = Column(
        String,
        unique=True,
        nullable=False
    )


class WhiteList(ConfigBase):
    __tablename__ = "white_list"

    id = Column(Integer, primary_key=True)

    timestamp = Column(
        DateTime,
        default=now_utc
    )

    url_id = Column(
        Integer,
        ForeignKey("urls.id"),
        nullable=True
    )

    exclude_header_id = Column(
        Integer,
        ForeignKey("exclude_headers.id"),
        nullable=True
    )

    block_keyword_id = Column(
        Integer,
        ForeignKey("block_key_words.id"),
        nullable=True
    )

    url = relationship(
        "Url",
        lazy="joined"
    )

    exclude_header = relationship(
        "ExcludeHeader",
        lazy="joined"
    )

    block_keyword = relationship(
        "BlockKeyWord",
        lazy="joined"
    )


# =========================================================
# ===================== HELPERS ===========================
# =========================================================

def config_is_empty():
    session = ConfigSessionLocal()

    try:
        return session.query(Configuration).first() is None

    finally:
        session.close()


# =========================================================
# ===================== POPULATE ==========================
# =========================================================

def populate():
    session = ConfigSessionLocal()

    try:

        # ===================================
        # CONFIG PADRÃO
        # ===================================

        if not session.query(Configuration).filter_by(id=1234).first():

            session.add(
                Configuration(
                    id=1234,
                    traffic_visible=32,
                    theme=Theme.DARK,
                )
            )

        # ===================================
        # URLS BASE
        # ===================================

        base_urls = [
            "google.com",
            "globo.com",
            "youtube.com",
            "facebook.com",
            "chatgpt.com",
            "x.com",
            "reddit.com",
            "doubleclick.net",
            "adservice.google.com",
            "analytics.google.com",
        ]

        for url_str in base_urls:

            exists = session.query(Url).filter_by(
                url=url_str
            ).first()

            if not exists:
                session.add(
                    Url(url=url_str)
                )

        session.flush()

        # ===================================
        # HEADERS
        # ===================================

        headers_to_exclude = [
            "Cookie",
            "Authorization",
            "Proxy-Authorization",
            "Set-Cookie",
            "X-CSRF-Token",
        ]

        for header in headers_to_exclude:

            exists = session.query(
                ExcludeHeader
            ).filter_by(
                field_name=header
            ).first()

            if not exists:
                session.add(
                    ExcludeHeader(
                        field_name=header
                    )
                )

        session.flush()

        # ===================================
        # DOMÍNIOS DE ANÚNCIO
        # ===================================

        ad_domains = [
            "doubleclick.net",
            "adservice.google.com",
        ]

        for domain in ad_domains:

            url_rec = session.query(Url).filter_by(
                url=domain
            ).first()

            if not url_rec:
                continue

            exists = session.query(AddDomain).filter_by(
                url_id=url_rec.id
            ).first()

            if not exists:
                session.add(
                    AddDomain(
                        url_id=url_rec.id
                    )
                )

        # ===================================
        # BLACKLIST
        # ===================================

        blacklist_domains = [
            "doubleclick.net"
        ]

        for domain in blacklist_domains:

            url_rec = session.query(Url).filter_by(
                url=domain
            ).first()

            if not url_rec:
                continue

            exists = session.query(BlackList).filter_by(
                url_id=url_rec.id
            ).first()

            if not exists:
                session.add(
                    BlackList(
                        url_id=url_rec.id
                    )
                )

        # ===================================
        # WHITELIST
        # ===================================

        whitelist_domains = [
            "google.com",
            "chatgpt.com",
        ]

        for domain in whitelist_domains:

            url_rec = session.query(Url).filter_by(
                url=domain
            ).first()

            if not url_rec:
                continue

            exists = session.query(WhiteList).filter_by(
                url_id=url_rec.id
            ).first()

            if not exists:
                session.add(
                    WhiteList(
                        url_id=url_rec.id
                    )
                )

        session.commit()

    except Exception as e:

        session.rollback()

        logger.exception(
            f"Erro ao popular banco: {e}"
        )

    finally:
        session.close()


# =========================================================
# ================= UPDATE CONFIGS ========================
# =========================================================

def update_configs(
    traffic_visible: int = 32,
    theme: Theme = Theme.DARK,
):

    session = ConfigSessionLocal()

    try:

        config = session.query(
            Configuration
        ).filter_by(
            id=1234
        ).first()

        if config:

            config.timestamp = now_utc()
            config.traffic_visible = traffic_visible
            config.theme = theme

        else:

            config = Configuration(
                id=1234,
                traffic_visible=traffic_visible,
                theme=theme,
            )

            session.add(config)

        session.commit()

    except Exception as e:

        session.rollback()

        logger.exception(
            f"Erro ao atualizar configs: {e}"
        )

    finally:
        session.close()


# =========================================================
# ===================== INIT DB ===========================
# =========================================================

def init_db():

    # TEMP
    TrafficBase.metadata.create_all(
        bind=traffic_engine
    )

    # CONFIG
    ConfigBase.metadata.create_all(
        bind=config_engine
    )

    if config_is_empty():
        populate()
        logger.info("Banco de configuração populado ✅")

    logger.info("Banco temporário pronto 🚀")
    logger.info("Banco de configuração pronto 🚀")


# =====================
# START
# =====================

init_db()