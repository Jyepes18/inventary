from pydantic import BaseModel

class ProductUpdate(BaseModel):
    category: str
    name: str
    quantity: int
