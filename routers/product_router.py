from collections import defaultdict
from typing import Annotated

from fastapi import Depends, HTTPException, APIRouter

import connexion_db
from schema.product import ProductUpdate
from schema.user import User
from service.auth import get_current_activate_user, not_user
from service.gemini import get_category
from service.verify import verify_power_user, verify_quantity

produc_router = APIRouter()

@produc_router.post("/users/add/product")
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
    
@produc_router.get("/users/view/products")
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
    

@produc_router.put("/users/update/product/{product_id}")
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
