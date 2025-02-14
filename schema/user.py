from pydantic import BaseModel

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