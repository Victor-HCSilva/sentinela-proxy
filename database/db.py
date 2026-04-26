from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text as SQLText
from sqlalchemy.orm import sessionmaker, declarative_base
import tempfile
from datetime import datetime
import os
from configs import general_settings

db_config = general_settings.get("db_config")


Base = declarative_base()
db_path = os.path.join(tempfile.gettempdir(), db_config.get("db_name"))
engine = create_engine(
    f'{db_config.get("engine_db_type")}{db_path}',
    connect_args={'check_same_thread': False}
)
SessionLocal = sessionmaker(bind=engine)


class TrafficLog(Base):
    __tablename__ = 'traffic_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now)
    host = Column(String)
    method = Column(String)
    size = Column(Integer)
    headers = Column(SQLText)
    payload = Column(SQLText)


if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)


