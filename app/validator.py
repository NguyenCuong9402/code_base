import json
import typing
from datetime import date
from app.enums import INVALID_PARAMETERS_ERROR
from marshmallow import Schema, fields, validate, ValidationError, types, validates_schema, post_dump
from app.utils import REGEX_EMAIL, REGEX_VALID_PASSWORD


class BaseValidation(Schema):

    def custom_validate(
            self,
            data: typing.Mapping,
            *,
            many: typing.Optional[bool] = None,
            partial: typing.Optional[typing.Union[bool, types.StrSequenceOrSet]] = None
    ) -> (bool, str):
        """Validate `data` against the schema, returning a dictionary of
        validation errors.

        :param data: The data to validate.
        :param many: Whether to validate `data` as a collection. If `None`, the
            value for `self.many` is used.
        :param partial: Whether to ignore missing fields and not require
            any fields declared. Propagates down to ``Nested`` fields as well. If
            its value is an iterable, only missing fields listed in that iterable
            will be ignored. Use dot delimiters to specify nested fields.
        :return: status validate and message_id.

        .. versionadded:: 1.1.0
        """
        try:
            self._do_load(data, many=many, partial=partial, postprocess=False)
        except ValidationError as exc:
            check = typing.cast(typing.Dict[str, typing.List[str]], exc.messages)
            if hasattr(self, 'define_message'):
                for key in check:
                    if key in self.define_message:
                        return False, self.define_message[key]
                return False, INVALID_PARAMETERS_ERROR
            else:
                # return check
                return False, INVALID_PARAMETERS_ERROR

        return True, ''


class AuthValidation(BaseValidation):
    """
    Validator auth
    :param
        email: string, required
        password: string, required
        is_admin: bool, required
    Ex:
    {
        "email": "admin@boot.ai",
        "password": "admin",
        "is_admin": true
    }
    """
    email = fields.String(required=True, validate=[validate.Length(min=1, max=50), validate.Regexp(REGEX_EMAIL)])
    password = fields.String(required=True,
                             validate=[validate.Length(min=1, max=16), validate.Regexp(REGEX_VALID_PASSWORD)])
    is_admin = fields.Boolean(required=True)

    define_message = {
        "email": "001"
    }


class UserSchema(Schema):
    id = fields.String()
    email = fields.String()
    phone = fields.String()
    full_name = fields.String()
    address = fields.String()
    avatar_url = fields.String()
    date_of_birth = fields.String()
    created_date = fields.Number()
    modified_date = fields.Number()
    type = fields.Number()
    created_user_id = fields.String()
