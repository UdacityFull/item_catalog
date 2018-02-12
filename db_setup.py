from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine


Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    name = Column(String(250), nullable = False)
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable = False)
    picture = Column(String(250))



class Category(Base):
    __tablename__ = 'category'

    name = Column(String(255), nullable = False)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="category")

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name'          : self.name,
            'id'            : self.id
        }

class Items(Base):
    __tablename__ = 'items'

    name = Column(String(250), nullable=False)
    id = Column(Integer, primary_key=True)
    desc = Column(String(250))
    date = Column(DateTime, nullable=False)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category, backref=backref('items', cascade='all, delete'))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="items")

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name'          : self.name,
            'id'            : self.id,
            'desc'   : self.desc,
            'category'      : self.category.name
        }


engine = create_engine('sqlite:///item_catalog.db')

Base.metadata.create_all(engine)