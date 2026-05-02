import enum
import os
import tempfile
from datetime import datetime, timezone
import logging 
from sqlalchemy.orm import DeclarativeMeta

from sqlalchemy import (
    create_engine, Column,
    Integer, String, DateTime, Text as SQLText,
    Enum as SQLEnum, ForeignKey, Boolean
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from typing import Type, List, Union
from sqlalchemy.orm import DeclarativeMeta, Session
from sqlalchemy.exc import SQLAlchemyError


# =====================
# CONFIG DB
# =====================
db_name = "sentinelaDB.db"

db_path = os.path.join(tempfile.gettempdir(), db_name)
DB_URL = f"sqlite:///{db_path}"

engine = create_engine(
    DB_URL,
    connect_args={'check_same_thread': False}
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

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


# =====================
# MODELS
# =====================
class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=now_utc)
    host = Column(String)
    method = Column(String)
    size = Column(Integer)
    headers = Column(SQLText)
    payload = Column(SQLText)


class Configuration(Base):
    __tablename__ = "configs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=now_utc)
    traffic_visible = Column(Integer)
    theme = Column(SQLEnum(Theme, native_enum=False), default=Theme.DARK, nullable=False)


class Url(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String, unique=True, nullable=False)


class AddDomain(Base):
    __tablename__ = "add_domains"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=now_utc)

    url_id = Column(Integer, ForeignKey("urls.id"))
    url = relationship("Url")

    is_active = Column(Boolean, default=True)


class BlockKeyWord(Base):
    __tablename__ = "block_key_words"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=now_utc)

    word = Column(String, unique=True, nullable=False)
    is_active = Column(Boolean, default=True)


class BlackList(Base):
    __tablename__ = "black_list"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=now_utc)

    url_id = Column(Integer, ForeignKey("urls.id"))
    url = relationship("Url")


class ExcludeHeader(Base):
    __tablename__ = "exclude_headers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=now_utc)
    field_name = Column(String, unique=True, nullable=False)


class WhiteList(Base):
    __tablename__ = "white_list"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=now_utc)

    url_id = Column(Integer, ForeignKey("urls.id"), nullable=True)
    exclude_header_id = Column(Integer, ForeignKey("exclude_headers.id"), nullable=True)
    block_keyword_id = Column(Integer, ForeignKey("block_key_words.id"), nullable=True)

    url = relationship("Url")
    exclude_header = relationship("ExcludeHeader")
    block_keyword = relationship("BlockKeyWord")


# =====================
# ORM OPERATIONS
# =====================
def is_empty():
    session = SessionLocal()
    try:
        return session.query(Configuration).first() is None
    finally:
        session.close()


def populate():
    session = SessionLocal()
    try:
        # Config padrão
        if not session.query(Configuration).filter_by(id=1234).first():
            session.add(Configuration(
                id=1234,
                traffic_visible=32,
                theme=Theme.DARK
            ))

        # URLs conhecidas
        urls_data = [
            'google.com',
            'globo.com',
            'youtube.com',
            'facebook.com',
            'chatgpt.com',
            'x.com',
            'reddit.com',
        ]

        for url_str in urls_data:
            # Verifica se a URL já existe antes de adicionar
            if not session.query(Url).filter_by(url=url_str).first():
                session.add(Url(url=url_str))
        session.flush()  # garante IDs disponíveis

        # Domínios de anúncios
        ads_ids = [4, 2]
        for uid in ads_ids:
            if not session.query(AddDomain).filter_by(url_id=uid).first():
                session.add(AddDomain(url_id=uid))

        # Blacklist
        if not session.query(BlackList).filter_by(url_id=2).first():
            session.add(BlackList(url_id=2))

        # Headers excluíveis
        # headers = ['cookie', 'User-Agent', 'Authorization']
        headers = []
        for h in headers:
            if not session.query(ExcludeHeader).filter_by(field_name=h).first():
                session.add(ExcludeHeader(field_name=h))

        # Whitelist
        whitelist_ids = [1, 3]
        for uid in whitelist_ids:
            if not session.query(WhiteList).filter_by(url_id=uid).first():
                session.add(WhiteList(url_id=uid))

        session.commit()
    finally:
        session.close()


def update_configs(traffic_visible: int = 32, theme: Theme = Theme.DARK):
    session = SessionLocal()
    try:
        config = session.query(Configuration).filter_by(id=1234).first()

        if config:
            config.timestamp = now_utc()
            config.traffic_visible = traffic_visible
            config.theme = theme
        else:
            config = Configuration(
                id=1234,
                traffic_visible=traffic_visible,
                theme=theme
            )
            session.add(config)

        session.commit()
    finally:
        session.close()


def init_db():
    logger = logging.getLogger(__name__)
    Base.metadata.create_all(bind=engine)

    if is_empty():
        populate()
        logger.info("Banco populado ✅")

    logging.info("Banco pronto 🚀")

init_db()
