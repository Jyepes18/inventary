import os
import jwt
import mysql
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from dotenv import load_dotenv
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

import connexion_db
from service.gemini import get_category
from schema.user import Token, TokenData, User, UserInDB
from schema.product import ProductUpdate


load_dotenv()

ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_sheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

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
    cursor = connexion_db.conexion.cursor()
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

def verify_email(email_address):
    try:
        cursor = connexion_db.conexion.cursor()
        sql = "SELECT email_address FROM user WHERE email_address = %s"
        data = (str(email_address),)
        cursor.execute(sql, data)
        result = cursor.fetchone()

        if result:
            return None
        
        return email_address
    except mysql.connector.Error as err:
        return {"error": f"Database error: {err}"}

@app.post("/users/add/user")
async def add_user(current_user: Annotated[User, Depends(get_current_activate_user)],
                   name: str, last_name: str, email_address: str, password: str, power_user: str):
    
    user = verify_power_user(current_user.email_address)
    
    if user is None:
        not_user()

    role = user[3] if user else None

    if role.lower() != "jefe":
        raise HTTPException(status_code=403, detail="Only 'jefe' can create users")
    
    not_exist_email = verify_email(email_address)
    
    if not_exist_email is None:
        return {"message" : f"{not_exist_email}, This email is into us"}
    
    cursor = connexion_db.conexion.cursor()
    sql = "INSERT INTO user (name, last_name, email_address, password) VALUES (%s, %s, %s, %s)"
    password_hash = get_password_hash(password)
    data = (name, last_name, not_exist_email, password_hash,)
    cursor.execute(sql, data)
    connexion_db.conexion.commit()

    id_rol = cursor.lastrowid

    sql_rol = "INSERT INTO rol (power, user_id) VALUES (%s, %s)"
    data_rol = (power_user, id_rol,)
    cursor.execute(sql_rol, data_rol)
    connexion_db.conexion.commit()
    cursor.close()

    return {"message": f"User {name} {last_name} {email_address} created successfully"}



def verify_quantity(quantity):
    if quantity <= 0:
        raise HTTPException(status_code=400, detail="Quantity can't be less than or equal to 0")
    return quantity

@app.post("/users/add/product")
async def add_products(current_user: Annotated[User, Depends(get_current_activate_user)],
category: str, name: str, quantity: int):
    user = verify_power_user(current_user.email_address)
    if user is None:
        not_user()
    try:
        category_ai = get_category(category, name)
        number = verify_quantity(quantity)
        cursor = connexion_db.conexion.cursor()
        sql = "INSERT INTO product(category, name, quantity) VALUES (%s, %s, %s)"
        data = (category_ai, name, number)
        cursor.execute(sql, data)
        connexion_db.conexion.commit()
        connexion_db.conexion.close()
        return {"message" : "Dates send succeful"}
    except HTTPException:
        return {"message" : "Problem to insetr dates"}
    
@app.get("/users/view/products")
async def view_products(current_user: Annotated[User, Depends(get_current_activate_user)]):
    user = verify_power_user(current_user.email_address)
    if user is None:
        not_user()
    
    try:
        cursor = connexion_db.conexion.cursor()
        sql = "SELECT category, name, quantity FROM product ORDER BY category"
        cursor.execute(sql)
        result = cursor.fetchall()
        connexion_db.conexion.close()

        if result is None:
            return {"message" : "No products found"}
        
        products_by_category = defaultdict(list)
        for category, name, quantity in result:
            products_by_category[category].append({"name" : name, "quantity" : quantity})
        
        return dict(products_by_category)

    except HTTPException:
        return {"message" : "Problem to found products"}
    
@app.get("/users/wiew/user")
async def view_users(current_user: Annotated[User, Depends(get_current_activate_user)]):
    user = verify_power_user(current_user.email_address)
    if user is None:
        not_user()
    try:
        cursor = connexion_db.conexion.cursor()
        sql = """SELECT u.id AS user_id, u.name, u.last_name, u.email_address, 
                r.power AS role FROM user u LEFT JOIN rol r ON u.id = r.user_id"""
        cursor.execute(sql)
        result = cursor.fetchall()


        if result is None:
            return {"message" : "No users found"}
        
        list_users = defaultdict(list)
        for user_id, name, last_name, email, role in result:
            list_users[user_id].append({
                "name" : name,
                "last_name" : last_name,
                "email" : email,
                "rol" : role if role else "This user dont have rol"
            })
        
        return dict(list_users)
    except HTTPException:
        return {"message" : "Problem to found user"}
        
    
@app.delete("/users/delte/user")
async def delete_user(current_user: Annotated[User, Depends(get_current_activate_user)], email_person: str):
    user = verify_power_user(current_user.email_address)
    if user is None:
        not_user()
    
    try:
        cursor = connexion_db.conexion.cursor()
        sql = "SELECT * FROM user WHERE email_address = %s"
        data = (email_person,)
        cursor.execute(sql, data)
        result = cursor.fetchall()

        if result is None:
            return {"message" : "No found user"}

        sql_delete = "DELETE FROM user WHERE email_address = %s"
        data_delete = (email_person,)
        cursor.execute(sql_delete, data_delete,)
        connexion_db.conexion.commit()
        return {"message" : "user delete successfuly"}
    except HTTPException:
        return {"message" : "Problems to delete user"}
    finally:
        connexion_db.conexion.close()
    
@app.put("/users/update/product/{product_id}")
async def update_product(current_user: Annotated[User, Depends(get_current_activate_user)], product_id: int, product: ProductUpdate):
    user = verify_power_user(current_user.email_address)
    if user is None:
        not_user()

    cursor = connexion_db.conexion.cursor()
    sql = "SELECT * FROM product WHERE id = %s"
    data = (product_id,)
    cursor.execute(sql, data)
    result = cursor.fetchall()

    if result is None:
        raise HTTPException(status_code=404, detail="El ID del producto no existe")
    
    verifi_category = get_category(product.category, product.name)
    
    sql_update = "UPDATE product SET category =%s, name =%s, quantity=%s WHERE id = %s"
    data_update = (verifi_category, product.name, product.quantity, product_id)
    cursor.execute(sql_update, data_update)
    connexion_db.conexion.commit()

    return {"message" : "Data update succesflu"}




    


