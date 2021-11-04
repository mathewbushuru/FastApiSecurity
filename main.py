'''
PASSWOrd FLOW
1. user types in username and password in frontend
2. FE sends username and password to specific url in api
3. api checks username and password and responds with token which will expire
4. FE stores this token somewhere
'''

#Note that OAuth2 uses 'form data' from 'python-multipart' library so install it from pip first
from fastapi import Depends, FastAPI,HTTPException,status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from typing import Optional
from pydantic import BaseModel

fake_users_db ={
    "johndoe":{
        "username":"johndoe",
        "full_name":"John Doe",
        "email":"johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled":False,
    },
    "janedoe":{
        "username":"janedoe",
        "full_name":"Jane Doe",
        "email":"janedoe@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled":True,
    },
}

app = FastAPI()

def fake_hash_password(password:str):
    return "fakehashed"+password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#Create a user model
class User(BaseModel):
    username: str 
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None  

class UserInDB(User):
    hashed_password:str 

def get_user(db,username:str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

#A fake utility function that take token and returns a user
def fake_decode_token(token):
    '''return User(
        username = token+"fakedecoded", email="fakeuser@fake.com", full_name = "Fake User"
    )'''
    user = get_user(fake_users_db,token)
    return user 

#This dependency with an oauth2scheme
async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid authentication credentials",
            headers = {"WWW-Authenticate":"Bearer"},
        )
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400,detail="Inactive user")
    return current_user 

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail = "Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password==user.hashed_password:
        raise HTTPException(status_code=400, detail = "Incorrect username or password") 

    return {"access_token": user.username, "token_type":"bearer"}

#Inject the current user
@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/items")
async def read_items(token: str = Depends(oauth2_scheme)):
    return {"token": token}