import pandas as pd

from flask import Blueprint, request
from sqlalchemy import or_
from app.models import Permission, Message
from app.api.helper import send_error, send_result
from app.extensions import db
from app.enums import MESSAGE_ID
from app.gateway import authorization_require
import uuid

api = Blueprint('manage/message', __name__)