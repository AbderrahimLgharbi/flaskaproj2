from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4

db=SQLAlchemy()

def get_uuid():
    return uuid4().hex

class User(db.Model):
    id = db.Column(db.String(11), primary_key=True,unique=True,default=get_uuid)
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.Text, nullable=False)
