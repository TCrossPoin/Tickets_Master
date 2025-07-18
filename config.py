# config.py
import os
from dotenv import load_dotenv

load_dotenv()  # Load variables from .env

MYSQL_HOST = os.getenv('MYSQL_HOST')
MYSQL_USER = os.getenv('MYSQL_USER')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
MYSQL_DB = os.getenv('MYSQL_DB')

SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY')
HEAD_SECRET_KEY = os.getenv('HEAD_SECRET_KEY')

MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
