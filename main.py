'''
PASSWOrd FLOW
1. user types in username and password in frontend
2. FE sends username and password to specific url in api
3. api checks username and password and responds with token which will expire
4. FE stores this token somewhere
'''

#Note that OAuth2 uses 'form data' from 'python-multipart' library so install it from pip first
from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordBearer

from typing import Optional
from pydantic import BaseModel

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#Create a user model
class User(BaseModel):
    username: str 
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None 

#A fake utility function that take token and returns a user
def fake_decode_token(token):
    return User(
        username = token+"fakedecoded", email="fakeuser@fake.com", full_name = "Fake User"
    )

#This dependency with an oauth2scheme
async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    return user

#Inject the current user
@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/items")
async def read_items(token: str = Depends(oauth2_scheme)):
    return {"token": token}