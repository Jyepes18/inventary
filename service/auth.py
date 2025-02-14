from fastapi import Depends, HTTPException, status
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import connexion_db
import os
from fastapi.security import OAuth2PasswordBearer
from typing import Annotated
from schema.user import UserInDB, TokenData, User
import jwt

load_dotenv()
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_sheme = OAuth2PasswordBearer(tokenUrl="token")

def not_user():
    raise HTTPException(status_code=400, detail="User does not have credentials to create a user")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email_address: str):
    cursor = connexion_db.conexion.cursor()
    sql = "SELECT name, last_name, email_address, password FROM user WHERE email_address = %s"
    data = (email_address,)
    cursor.execute(sql, data)
    data_user = cursor.fetchone()
    if data_user:
        user_dict = {
            'name': data_user[0],
            'last_name': data_user[1],
            'email_address': data_user[2],
            'hashed_password': data_user[3]
        }
        return UserInDB(**user_dict)

def authenticate_user(email_address: str, password: str):
    user = get_user(email_address)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(microseconds=15)
    to_encode.update({"exp" : expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_sheme)]):
    credentials_exceptions = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate" : "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email_address: str = payload.get("sub")
        if email_address is None:
            return credentials_exceptions
        token_data = TokenData(email_address=email_address)
    except InvalidTokenError:
        raise credentials_exceptions
    user =  get_user(email_address=token_data.email_address)
    if user is None:
        raise credentials_exceptions
    return user

async def get_current_activate_user(
        current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return current_user