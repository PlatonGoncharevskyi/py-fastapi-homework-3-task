from pydantic import BaseModel, EmailStr, field_validator

from database.validators.accounts import validate_email, validate_password_strength


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator('email')
    @classmethod
    def check_email(cls, value: str) -> str:
        return validate_email(value)


    @field_validator('password')
    @classmethod
    def check_password(cls, value: str) -> str:
        return validate_password_strength(value)



class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

class MessageResponseSchema(BaseModel):
    message: str = "User account activated successfully."


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str