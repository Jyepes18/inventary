from fastapi import FastAPI
from routers.auth_router import auth_router
from routers.user_router import user_router
from routers.product_router import produc_router

app = FastAPI()

app.include_router(auth_router,tags=["Authentication"])
app.include_router(user_router,tags=["Users"])
app.include_router(produc_router, tags=["Products"])



    
