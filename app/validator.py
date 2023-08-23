import typing
from app.enums import INVALID_PARAMETERS_ERROR
from marshmallow import Schema, fields, validate, ValidationError, types, validates_schema, post_dump
from app.utils import REGEX_EMAIL, REGEX_VALID_PASSWORD, REGEX_FULLNAME_VIETNAMESE


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


class GetUserValidation(BaseValidation):

    page = fields.Integer(required=False)
    page_size = fields.Integer(required=False)
    search_name = fields.String(required=False, validate=validate.Length(min=0, max=200))
    status = fields.Integer(required=False, validate=validate.OneOf([0, 1]))
    sort = fields.String(required=False,
                         validate=validate.OneOf(
                             ["full_name", "email", "modified_date", "created_date", "created_user",
                              "status"]))
    order_by = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))


class GetGroupValidation(BaseValidation):

    page = fields.Integer(required=False)
    page_size = fields.Integer(required=False)
    search_name = fields.String(required=False, validate=validate.Length(min=0, max=200))
    sort = fields.String(required=False,
                         validate=validate.OneOf(
                             ["key", "name", "description", "created_date", "created_user"]))
    order_by = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))


class GetRoleValidation(BaseValidation):

    page = fields.Integer(required=False)
    page_size = fields.Integer(required=False)
    search_name = fields.String(required=False, validate=validate.Length(min=0, max=200))
    sort = fields.String(required=False,
                         validate=validate.OneOf(
                             ["key", "name", "description", "created_date", "created_user"]))
    order_by = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))


class UserValidation(BaseValidation):
    full_name = fields.String(required=True,
                              validate=[validate.Length(min=1, max=50), validate.Regexp(REGEX_FULLNAME_VIETNAMESE)])
    email = fields.String(required=True, validate=[validate.Length(min=3, max=50), validate.Regexp(REGEX_EMAIL)])
    status = fields.Boolean(required=True)
    group_ids = fields.List(fields.String(validate=validate.Length(max=50)))
    role_ids = fields.List(fields.String(validate=validate.Length(max=50)))


class RegisterValidation(BaseValidation):
    full_name = fields.String(required=True,
                              validate=[validate.Length(min=1, max=50), validate.Regexp(REGEX_FULLNAME_VIETNAMESE)])
    email = fields.String(required=True, validate=[validate.Length(min=3, max=50), validate.Regexp(REGEX_EMAIL)])
    password = fields.String(required=True)
    phone = fields.String(required=True)
    address = fields.String(required=True)


class AuthValidation(BaseValidation):
    email = fields.String(required=True, validate=[validate.Length(min=1, max=50), validate.Regexp(REGEX_EMAIL)])
    password = fields.String(required=True,
                             validate=[validate.Length(min=1, max=16), validate.Regexp(REGEX_VALID_PASSWORD)])
    is_admin = fields.Boolean(required=True)

    define_message = {
        "email": "001"
    }


class VerifyPasswordValidation(Schema):

    current_password = fields.String(required=True,
                                     validate=[validate.Length(min=1, max=16), validate.Regexp(REGEX_VALID_PASSWORD)])


class UpdateProfileSchema(Schema):
    email = fields.String(validate=[validate.Regexp(REGEX_EMAIL)])
    phone = fields.String()
    full_name = fields.String(validate=[validate.Regexp(REGEX_FULLNAME_VIETNAMESE)])
    address = fields.String()
    birthday = fields.String()


class PostGroupValidator(Schema):
    key = fields.String(required=True)
    name = fields.String(required=True)
    description = fields.String()
    role_ids = fields.List(fields.String(), required=True)


class UpdateGroupValidator(Schema):
    name = fields.String()
    description = fields.String()
    role_ids = fields.List(fields.String(), required=True)


class PasswordValidation(Schema):

    password = fields.String(required=True,
                             validate=[validate.Length(min=1, max=16), validate.Regexp(REGEX_VALID_PASSWORD)])
    current_password = fields.String(required=True,
                                     validate=[validate.Length(min=1, max=16), validate.Regexp(REGEX_VALID_PASSWORD)])


class DeleteGroupValidator(Schema):
    group_ids = fields.List(fields.String(), required=True)
    is_delete_all = fields.Boolean()


class DeleteRoleValidator(Schema):
    group_ids = fields.List(fields.String(), required=True)
    is_delete_all = fields.Boolean()


class UpdateRoleValidator(Schema):
    type = fields.Integer()
    description = fields.String()
    name = fields.String()


class PostRoleValidator(Schema):
    key = fields.String(required=True)
    name = fields.String(required=True)
    description = fields.String()
    role_type = fields.Integer(required=True)


class ChangeUserValidation(Schema):
    is_active = fields.Boolean()
    group_ids = fields.List(fields.String())
    role_ids = fields.List(fields.String())


class UserParentSchema(Schema):
    id = fields.String()
    email = fields.String()
    phone = fields.String()
    full_name = fields.String()
    address = fields.String()
    birthday = fields.String()


class UserSchema(Schema):
    id = fields.String()
    email = fields.String()
    phone = fields.String()
    full_name = fields.String()
    address = fields.String()
    birthday = fields.String()
    created_date = fields.Number()
    modified_date = fields.Number()
    type = fields.Number()
    avatar_url = fields.String()
    is_active = fields.Boolean()
    status = fields.Boolean()
    created_user_id = fields.String()
    last_modified_user_id = fields.String()
    created_user = fields.Nested(UserParentSchema)


class GroupSchema(Schema):
    id = fields.String()
    key = fields.String()
    name = fields.String()
    description = fields.String()
    created_date = fields.Integer()
    modified_date = fields.Integer()
    modified_user_data = fields.Nested(UserParentSchema)
    created_user_data = fields.Nested(UserParentSchema)


class RoleSchema(Schema):
    id = fields.String()
    key = fields.String()
    name = fields.String()
    description = fields.String()
    type = fields.Integer()
    created_date = fields.Integer()
    modified_date = fields.Integer()
    modified_user_data = fields.Nested(UserParentSchema)
    created_user_data = fields.Nested(UserParentSchema)





