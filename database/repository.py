from typing import Type, List, Union
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from .db import SessionLocal

class Repository:
    def __init__(self, table: Type, session: Session = None) -> None:
        self.table = table
        self._external_session = session
        # Pegamos as colunas para validação sem precisar de uma sessão aberta
        self.valid_fields: List[str] = table.__table__.columns.keys()

    def _get_session(self) -> Session:
        return self._external_session if self._external_session else SessionLocal()

    def is_valid(self, keys: Union[List[str], set]) -> bool:
        return all(key in self.valid_fields for key in keys)

    def create(self, **kwargs) -> bool:
        if not self.is_valid(kwargs.keys()): return False
        session = self._get_session()
        try:
            obj = self.table(**kwargs)
            session.add(obj)
            session.commit()
            return True
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            if not self._external_session: session.close()

    def update(self, id: int, **kwargs) -> bool:
        if not self.is_valid(kwargs.keys()): return False
        session = self._get_session()
        try:
            rows = session.query(self.table).filter_by(id=id).update(kwargs)
            session.commit()
            return rows > 0
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            if not self._external_session: session.close()
            
    def delete(self, id: int) -> bool:
        """Deleta a instância pelo ID de forma segura"""
        session = self._get_session()
        try:
            rows_deleted = session.query(self.table).filter_by(id=id).delete()
            session.commit()
            return rows_deleted > 0
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            if not self._external_session: session.close()
