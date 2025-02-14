from datetime import timedelta
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends, HTTPException, status, APIRouter
from schema.user import Token, User
from service.auth import ACCESS_TOKEN_EXPIRE_MINUTES, authenticate_user, create_access_token, get_current_activate_user

auth_router = APIRouter()

@auth_router.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(data={"sub": user.email_address}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")

@auth_router.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_activate_user)],
):
    return current_user