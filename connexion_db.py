import mysql.connector

conexion = mysql.connector.connect(
    host = "localhost",
    user = "root",
    password = "",
    database = "inventario"
)

cursor = conexion.cursor()


