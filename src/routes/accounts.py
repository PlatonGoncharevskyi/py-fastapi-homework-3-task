from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload, selectinload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import MessageResponseSchema, UserActivationRequestSchema, PasswordResetCompleteRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema
from schemas.accounts import UserRegistrationResponseSchema, UserRegistrationRequestSchema, PasswordResetRequestSchema, \
    TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()

@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def create_new_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    existing_email = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    if existing_email:
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")

    query = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db.execute(query)
    user_group = result.scalar_one_or_none()

    try:

        db_user = UserModel.create(email=user_data.email, raw_password=user_data.password, group_id=user_group.id)
        db.add(db_user)
        await db.flush()
        token = ActivationTokenModel(user_id=db_user.id)
        db.add(token)
        await db.commit()
        await db.refresh(db_user)
        return db_user
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred during user creation.")


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user_token(user_act: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    query = select(UserModel).join(UserModel.activation_token).where(
        (UserModel.email == user_act.email),
        (ActivationTokenModel.token == user_act.token)
    ).options(selectinload(UserModel.activation_token))

    res = await db.execute(query)
    user_data = res.scalar_one_or_none()

    if not user_data:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    token = user_data.activation_token
    expires_at = token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if user_data.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user_data.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema()


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def user_password_reset(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    query = select(UserModel).where(UserModel.email == user_data.email).options(selectinload(UserModel.password_reset_token))
    res = await db.execute(query)
    user = res.scalar_one_or_none()

    if not user or not user.is_active:
        return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")

    if user.password_reset_token:
        await db.delete(user.password_reset_token)

    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))

    db.add(reset_token)
    await db.commit()

    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")



@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def user_password_reset_complete(user_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    query = (
        select(UserModel)
        .join(UserModel.password_reset_token)
        .where(UserModel.email == user_data.email, PasswordResetTokenModel.token == user_data.token)
        .options(selectinload(UserModel.password_reset_token))
    )

    res = await db.execute(query)
    user = res.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token = user.password_reset_token
    expires_at = token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = user_data.password
        await db.delete(token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def user_login(
        user_data:UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    query = select(UserModel).where(UserModel.email == user_data.email)
    res = await db.execute(query)
    user = res.scalar_one_or_none()

    if not user or not user.verify_password(user_data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    data_to_encode = {"sub": str(user.id), "user_id": user.id}
    access_token = jwt_manager.create_access_token(data=data_to_encode)

    expires_delta = timedelta(days=settings.LOGIN_TIME_DAYS)
    refresh_token = jwt_manager.create_refresh_token(data=data_to_encode, expires_delta=expires_delta)
    try:
        refresh_token_db = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS,
        )
        db.add(refresh_token_db)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token)


@router.post("/api/v1/accounts/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_token_user(
        user_token: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(user_token.refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired or is invalid.")

    query = (
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == user_token.refresh_token)
        .options(selectinload(RefreshTokenModel.user))
    )
    res = await db.execute(query)
    user_db_token = res.scalar_one_or_none()

    if not user_db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    if not user_db_token.user:
        raise HTTPException(status_code=404, detail="User not found.")




    data_to_encode = {"sub": str(user_db_token.user.id), "user_id": user_db_token.user.id}
    access_token = jwt_manager.create_access_token(data=data_to_encode)

    return TokenRefreshResponseSchema(access_token=access_token)