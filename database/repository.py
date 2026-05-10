from typing import List, Type, Union

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload

from .db import (
    AddDomain,
    BlackList,
    ConfigSessionLocal,
    TrafficLog,
    TrafficSessionLocal,
    WhiteList,
)


class Repository:
    def __init__(self, model: Type, session: Session = None):

        self.model = model
        self._external_session = session
        self.valid_fields = model.__table__.columns.keys()

    def _get_session(self) -> Session:
        if self._external_session:
            return self._external_session
        if self.model == TrafficLog:
            return TrafficSessionLocal()
        return ConfigSessionLocal()

    def is_valid(self, keys: Union[List[str], set]) -> bool:
        return all(key in self.valid_fields for key in keys)

    def create(self, **kwargs) -> bool:
        if not self.is_valid(kwargs.keys()):
            return False
        session = self._get_session()
        try:
            obj = self.model(**kwargs)
            session.add(obj)
            session.commit()
            return True
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            if not self._external_session:
                session.close()

    def update(self, id: int, **kwargs) -> bool:
        if not self.is_valid(kwargs.keys()):
            return False
        session = self._get_session()
        try:
            rows = session.query(self.model).filter_by(id=id).update(kwargs)
            session.commit()
            return rows > 0
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            if not self._external_session:
                session.close()

    def delete(self, id: int) -> bool:
        """Deleta a instância pelo ID de forma segura"""
        session = self._get_session()
        try:
            rows_deleted = session.query(self.model).filter_by(id=id).delete()
            session.commit()
            return rows_deleted > 0
        except SQLAlchemyError:
            session.rollback()
            return False
        finally:
            if not self._external_session:
                session.close()

    #
    def get_all(self):
        db = TrafficSessionLocal() if self.model == TrafficLog else ConfigSessionLocal()

        try:
            query = db.query(self.model)

            # modelos com relacionamento URL
            if self.model in [BlackList, WhiteList, AddDomain]:
                query = query.options(joinedload(self.model.url))

            return query.all()

        finally:
            db.close()
