# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'supersecretkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'  # Usando SQLite como banco de dados
    SQLALCHEMY_TRACK_MODIFICATIONS = False
