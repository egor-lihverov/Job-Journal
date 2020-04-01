import datetime
import sqlalchemy
from sqlalchemy import orm
from .db_session import SqlAlchemyBase


# import sqlalchemy as sa
# import sqlalchemy.orm as orm
# from sqlalchemy.orm import Session
# mport sqlalchemy.ext.declarative as dec

# SqlAlchemyBase = dec.declarative_base()
class Departments(SqlAlchemyBase):
    __tablename__ = 'dapartament'
    id = sqlalchemy.Column(sqlalchemy.Integer,
                           primary_key=True, autoincrement=True)
    title = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    chief = sqlalchemy.Column(sqlalchemy.Integer,
                              sqlalchemy.ForeignKey("users.id"))
    members = sqlalchemy.Column(sqlalchemy.String,
                                sqlalchemy.ForeignKey("jobs.collaborators"))
    email = sqlalchemy.Column(sqlalchemy.String,
                              index=True, unique=True, nullable=True)
    user = orm.relation('User')
    job = orm.relation('Jobs')



