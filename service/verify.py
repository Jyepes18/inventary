from fastapi import HTTPException
import mysql
import connexion_db

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

def verify_quantity(quantity):
    if quantity <= 0:
        raise HTTPException(status_code=400, detail="Quantity can't be less than or equal to 0")
    return quantity
