from datetime import datetime, timedelta, timezone
from typing import Annotated
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel
import connexion
from dotenv import load_dotenv
import os
from google import genai

load_dotenv()

ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
SECRET_KEY_GEMINI = os.getenv("SECRET_KEY_GEMINI")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email_address: str | None = None
class User(BaseModel):
    name: str
    last_name: str
    email_address: str
    disabled: bool | None = None
class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_sheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email_address: str):
    cursor = connexion.conexion.cursor()
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

@app.post("/token")
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

@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_activate_user)],
):
    return current_user

def verify_power_user(email):
    cursor = connexion.conexion.cursor()
    sql = """
        SELECT u.id, u.name, u.last_name, COALESCE(r.power, 'Sin rol') 
        FROM user u 
        LEFT JOIN rol r ON u.id = r.user_id 
        WHERE u.email_address = %s
    """
    data = (email,)
    cursor.execute(sql, data)
    result = cursor.fetchone()
    cursor.close()
    return result if result else None

@app.post("/users/add/user")
async def add_user(current_user: Annotated[User, Depends(get_current_activate_user)],
                   name: str, last_name: str, email_address: str, password: str, power_user: str):
    
    user = verify_power_user(current_user.email_address)
    
    if user is None:
        raise HTTPException(status_code=400, detail="User does not have credentials to create a user")
    
    role = user  

    if role.lower() != "jefe":
        raise HTTPException(status_code=403, detail="Only 'jefe' can create users")
    
    cursor = connexion.conexion.cursor()
    sql = "INSERT INTO user (name, last_name, email_address, password) VALUES (%s, %s, %s, %s)"
    password_hash = get_password_hash(password)
    data = (name, last_name, email_address, password_hash)
    cursor.execute(sql, data)
    connexion.conexion.commit()

    id_rol = cursor.lastrowid

    sql_rol = "INSERT INTO rol (power, user_id) VALUES (%s, %s)"
    data_rol = (power_user, id_rol)
    cursor.execute(sql_rol, data_rol)
    connexion.conexion.commit()
    cursor.close()

    return {"message": f"User {name} {last_name} {email_address} created successfully"}

def get_category(category, name):
    client = genai.Client(api_key=SECRET_KEY_GEMINI)

    prompt = (
    f"El nombre '{name}' pertenece a la categoría '{category}'? "
    "Si no, responde únicamente con la categoría correcta, sin explicaciones ni contexto adicional."
    )

    response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
    print(response.text)
    return response.text

def verify_quantity(quantity):
    if quantity <= 0:
        raise HTTPException(status_code=400, detail="Quantity can't be less than or equal to 0")
    return quantity

@app.post("/users/add/product")
async def add_products(current_user: Annotated[User, Depends(get_current_activate_user)],
    category: str, name: str, quantity: int):
    user = verify_power_user(current_user.email_address)
    if user is None:
        raise HTTPException(status_code=400, detail="User does not have credentials to create a user")
    try:
        category_ai = get_category(category, name)
        number = verify_quantity(quantity)
        cursor = connexion.conexion.cursor()
        sql = "INSERT INTO product(category, name, quantity) VALUES (%s, %s, %s)"
        data = (category_ai, name, number)
        cursor.execute(sql, data)
        connexion.conexion.commit()
        connexion.conexion.close()
        return {"message" : "Dates send succeful"}
    except HTTPException:
        return {"message" : "Problem to insetr dates"}
    

