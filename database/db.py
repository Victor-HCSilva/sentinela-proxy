import enum
import os
import tempfile
from datetime import datetime, timezone

from sqlalchemy import (
    create_engine, Column,
    Integer, String, DateTime, Text as SQLText,
    Enum, text, ForeignKey, Boolean
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

from configs import general_settings, tables_names

# =====================
# CONFIG DB
# =====================
db_config = general_settings.get("db_config")

Base = declarative_base()

db_path = os.path.join(tempfile.gettempdir(), db_config.get("db_name"))

engine = create_engine(
    f'{db_config.get("engine_db_type")}{db_path}',
    connect_args={'check_same_thread': False}
)

SessionLocal = sessionmaker(bind=engine)


# =====================
# ENUMS
# =====================
class Theme(enum.Enum):
    DARK = "Dark"
    LIGHT = "Light"
    SYSTEM = "System"


# =====================
# MODELS
# =====================
class TrafficLog(Base):
    __tablename__ = tables_names.get("traffic_log")

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    host = Column(String)
    method = Column(String)
    size = Column(Integer)
    headers = Column(SQLText)
    payload = Column(SQLText)


class Configuration(Base):
    __tablename__ = tables_names.get("configs")

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    traffic_visible = Column(Integer)
    theme = Column(Enum(Theme, native_enum=False), default=Theme.DARK, nullable=False)


class Url(Base):
    __tablename__ = tables_names.get("urls")

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String, unique=True, nullable=False)


class AddDomain(Base):
    __tablename__ = tables_names.get("adds_domains")

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    url_id = Column(Integer, ForeignKey(f"{tables_names.get('urls')}.id"))
    url = relationship("Url")

    is_active = Column(Boolean, default=True)


class BlockKeyWord(Base):
    __tablename__ = tables_names.get("block_key_words")

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    word = Column(String, unique=True, nullable=False)
    is_active = Column(Boolean, default=True)


class BlackList(Base):
    __tablename__ = tables_names.get("black_list")

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    url_id = Column(Integer, ForeignKey(f"{tables_names.get('urls')}.id"))
    url = relationship("Url")


class ExcludeHeader(Base):
    __tablename__ = tables_names.get("exclude_headers")

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    field_name = Column(String, unique=True, nullable=False)


class WhiteList(Base):
    __tablename__ = tables_names.get("white_list")

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    url_id = Column(Integer, ForeignKey(f"{tables_names.get('urls')}.id"), nullable=True)
    exclude_header_id = Column(Integer, ForeignKey(f"{tables_names.get('exclude_headers')}.id"), nullable=True)
    block_keyword_id = Column(Integer, ForeignKey(f"{tables_names.get('block_key_words')}.id"), nullable=True)

    url = relationship("Url")
    exclude_header = relationship("ExcludeHeader")
    block_keyword = relationship("BlockKeyWord")


# =====================
# POPULATE DB (SQL FILE)
# =====================
def populate():
    with engine.raw_connection() as conn:
        with open("populate.sql", "r", encoding="utf-8") as f:
            conn.executescript(f.read())


# =====================
# CHECK SE BANCO ESTÁ VAZIO
# =====================
def is_empty():
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT 1 FROM {tables_names.get('configs')} LIMIT 1"))
        return result.first() is None


# =====================
# UPDATE CONFIG
# =====================
def update_configs(traffic_visible: int = 32, theme: str = "Dark"):
    with engine.connect() as conn:
        conn.execute(
            text(f"""
                UPDATE {tables_names.get("configs")}
                SET 
                    timestamp = :timestamp,
                    traffic_visible = :traffic,
                    theme = :theme
                WHERE id = 1234
            """),
            {
                "timestamp": datetime.now(timezone.utc),
                "traffic": traffic_visible,
                "theme": theme,
            }
        )
        conn.commit()


# =====================
# INIT
# =====================
if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)

    if is_empty():
        populate()

    print("Banco pronto 🚀")

