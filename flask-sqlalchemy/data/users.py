import datetime
import sqlalchemy
from flask_login import UserMixin
from sqlalchemy import orm
from werkzeug.security import generate_password_hash, check_password_hash

from .db_session import SqlAlchemyBase


# import sqlalchemy as sa
# import sqlalchemy.orm as orm
# from sqlalchemy.orm import Session
# mport sqlalchemy.ext.declarative as dec

# SqlAlchemyBase = dec.declarative_base()


class User(SqlAlchemyBase, UserMixin):
    __tablename__ = 'users'

    id = sqlalchemy.Column(sqlalchemy.Integer,
                           primary_key=True, autoincrement=True)
    surname = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    name = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    age = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)

    position = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    speciality = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    address = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    email = sqlalchemy.Column(sqlalchemy.String,
                              index=True, unique=True, nullable=True)
    hashed_password = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    created_date = sqlalchemy.Column(sqlalchemy.DateTime,
                                     default=datetime.datetime.now)
    news = orm.relation("Jobs", back_populates='user')

    # 3dapartament = orm.relation("Departament", back_populates='user')

    def __repr__(self):
        return '<Colonist>' + ' ' + self.name + ' ' + self.surname

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)


class Jobs(SqlAlchemyBase):
    __tablename__ = 'jobs'

    id = sqlalchemy.Column(sqlalchemy.Integer,
                           primary_key=True, autoincrement=True)
    team_leader = sqlalchemy.Column(sqlalchemy.Integer,
                                    sqlalchemy.ForeignKey("users.id"))
    job = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    work_size = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)
    collaborators = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    start_date = sqlalchemy.Column(sqlalchemy.DateTime)
    end_date = sqlalchemy.Column(sqlalchemy.DateTime)
    is_finished = sqlalchemy.Column(sqlalchemy.Boolean, nullable=True)
    user = orm.relation('User')
    # dapartament = orm.relation("Departament", back_populates='job')


#class News(SqlAlchemyBase):
#    __tablename__ = 'news'
#
#    id = sqlalchemy.Column(sqlalchemy.Integer,
#                           primary_key=True, autoincrement=True)
#    title = sqlalchemy.Column(sqlalchemy.String, nullable=True)
#    content = sqlalchemy.Column(sqlalchemy.String, nullable=True)
#    created_date = sqlalchemy.Column(sqlalchemy.DateTime,
#                                     default=datetime.datetime.now)
#    is_private = sqlalchemy.Column(sqlalchemy.Boolean, default=True)#
#
#    user_id = sqlalchemy.Column(sqlalchemy.Integer,
#                                sqlalchemy.ForeignKey("users.id"))
#    user = orm.relation('User')
    # categories = orm.relation("Category",
    #                          secondary="association",
    #                          backref="news")

# association_table = sqlalchemy.Table('association', SqlAlchemyBase.metadata,
#    sqlalchemy.Column('news', sqlalchemy.Integer,
#                      sqlalchemy.ForeignKey('news.id')),
#    sqlalchemy.Column('category', sqlalchemy.Integer,
#                      sqlalchemy.ForeignKey('category.id')))

# class Category(SqlAlchemyBase):
#    __tablename__ = 'category'
#    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True,
#                           autoincrement=True)
#    name = sqlalchemy.Column(sqlalchemy.String, nullable=True)
