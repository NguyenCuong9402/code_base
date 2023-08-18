from time import time


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