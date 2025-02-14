from collections import defaultdict
from typing import Annotated

from fastapi import Depends, HTTPException, APIRouter

import connexion_db
from schema.user import User
from service.auth import get_current_activate_user, get_password_hash, not_user
from service.verify import verify_email, verify_power_user

user_router = APIRouter()

@user_router.post("/users/add/user")
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

@user_router.get("/users/wiew/user")
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
    
@user_router.delete("/users/delte/user")
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