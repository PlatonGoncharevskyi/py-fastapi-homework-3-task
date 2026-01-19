from datetime import datetime, timezone
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
from schemas import MessageResponseSchema, UserActivationRequestSchema, PasswordResetCompleteRequestSchema
from schemas.accounts import UserRegistrationResponseSchema, UserRegistrationRequestSchema, PasswordResetRequestSchema
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
        raise HTTPException(status_code=400, detail="Invalid token or email.")

    token = user_data.activation_token

    if user_data.is_active is True:
        raise HTTPException(status_code=400, detail="User account is already active.")

    if token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user_data.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema()


@router.post("/password-reset/request/", response_model=PasswordResetCompleteRequestSchema)
async def user_password_reset(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    query = select(UserModel).where(UserModel.email == user_data.email)
    res = await db.execute(query)
    user = res.scalar_one_or_none()

    
