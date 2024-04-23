from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context
from alembic import config

from models import Base
from db import SQLALCHEMY_DATABASE_URL


target_metadata = Base.metadata
config.set_main_option("sqlalchemy.url", SQLALCHEMY_DATABASE_URL)
