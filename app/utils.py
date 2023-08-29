from time import time, strftime
import string
import random
from .enums import TIME_FORMAT_LOG
from .extensions import logger
import urllib.parse
from flask import request


def get_timestamp_now():
    """
        Returns:
            current time in timestamp
    """
    return int(time())


def data_preprocessing(cls_validator, input_json: dict):
    """
    Data preprocessing trim then check validate
    :param cls_validator:
    :param input_json:
    :return: status of class validate
    """
    for key, value in input_json.items():
        if isinstance(value, str):
            input_json[key] = value.strip()
    return cls_validator().custom_validate(input_json)


def generate_password():
    """
    :return: random password
    """
    symbol_list = ["@", "$", "!", "%", "*", "?", "&"]
    number = '0123456789'
    letters_and_digits = string.ascii_letters + string.digits
    result_str = ''.join(random.choices(letters_and_digits, k=6))
    return '{}{}{}'.format(result_str, random.choice(symbol_list), random.choice(number))


def logged_input(json_req: str) -> None:
    """
    Logged input fields
    :param json_req:
    :return:
    """

    logger.info('%s %s %s %s %s INPUT FIELDS: %s',
                strftime(TIME_FORMAT_LOG),
                request.remote_addr,
                request.method,
                request.scheme,
                request.full_path,
                json_req)


def normalize_search_input(search_name: str):
    """ normalize input string in utf-8

    Args:
        search_name: string

    Returns:

    """
    search_name = urllib.parse.unquote(search_name, encoding='utf-8', errors='replace') if search_name else None
    if search_name:
        search_name = search_name.strip()
        search_name = escape_wildcard(search_name)
    return search_name


def escape_wildcard(search):
    """
    :param search:
    :return:
    """
    search1 = str.replace(search, '\\', r'\\')
    search2 = str.replace(search1, r'%', r'\%')
    search3 = str.replace(search2, r'_', r'\_')
    search4 = str.replace(search3, r'[', r'\[')
    search5 = str.replace(search4, r'"', r'\"')
    search6 = str.replace(search5, r"'", r"\'")
    return search6


def trim_dict(input_dict: dict) -> dict:
    """

    Args:
        input_dict:

    Returns:

    """
    # trim dict
    new_dict = {}
    for key, value in input_dict.items():
        if isinstance(value, str):
            new_dict[key] = value.strip()
        else:
            new_dict[key] = value
    return new_dict


# Regex validate
RE_ONLY_NUMBERS = r'^(\d+)$'
RE_ONLY_CHARACTERS = r'^[a-zA-Z]+$'
RE_ONLY_NUMBER_AND_DASH = r'^[-\d]+$'
RE_ONLY_LETTERS_NUMBERS_PLUS = r'^[+A-Za-z0-9]+$'
REGEX_EMAIL = r'^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,' \
              r';:\s@\"]{2,})$'
REGEX_PHONE_NUMBER = r'^\+?[1-9]|^[0-9]{0,20}$'
REGEX_OTP = r'[0-9]{6}'
REGEX_FULLNAME_VIETNAMESE = r"([^0-9`~!@#$%^&*(),.?'\":;{}+=|<>_\-\\\/\[\]]+)$"
REGEX_URL = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<" \
             r">]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

REGEX_ADDRESS_VIETNAMESE = r"([^`~!@#$%^&*().?'\":;{}+=|<>_\-\\\[\]]+)$"
REGEX_VALID_PASSWORD = r'^(?=.*[0-9])(?=.*[a-zA-Z])(?!.* ).{8,16}$'
