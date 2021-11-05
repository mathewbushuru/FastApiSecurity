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

from datetime import datetime, timedelta 
from jose import JWTError, jwt
from passlib.context import CryptContext

#After running openssl rand -hex 32
SECRET_KEY = "6050af595ee7bec9b2005ce86d4794c01facdf097012993883e2531fef98c741"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db ={
    "johndoe":{
        "username":"johndoe",
        "full_name":"John Doe",
        "email":"johndoe@example.com",
        "hashed_password": '$2b$12$8f0.QphObKXbGJUJIl8KC.XOA3i1zOJzMSeYXK988cvGMyuDtZa..',
        "disabled":False,
    },
    "janedoe":{
        "username":"janedoe",
        "full_name":"Jane Doe",
        "email":"janedoe@example.com",
        "hashed_password": '$2b$12$D6efnsevN20PdMk/zhU.cOOviqQM5PbHQgli7/YOHMOlf1pIr8Ga2',
        "disabled":True,
    },
}

class Token(BaseModel):
    access_token:str 
    token_type:str 

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str 
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None 

class UserInDB(User):
    hashed_password:str  

pwd_context = CryptContext(schemes = ["bcrypt"], deprecated = "auto") 

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") 

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password,hashed_password) 

def get_password_hash(password):
    return pwd_context.hash(password)

'''def fake_hash_password(password:str):
    return "fakehashed"+password'''

def get_user(db,username:str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db,username:str,password:str):
    user = get_user(fake_db,username)
    if not user:
        return False
    if not verify_password(password,user.hashed_password):
        return False 
    return user 

def create_access_token(data:dict, expires_delta:Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt

#A fake utility function that take token and returns a user
'''def fake_decode_token(token):
    #return User(
       # $=username = token+"fakedecoded", email="fakeuser@fake.com", #full_name = "Fake User"
    #)
    user = get_user(fake_users_db,token)
    return user '''

#This dependency with an oauth2scheme
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Could not validate credentials",
        headers = {"WWW-Authenticate":"Bearer"},
    )
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username:str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    #user = fake_decode_token(token)
    user = get_user(fake_users_db,username=token_data.username)
    '''if not user:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid authentication credentials",
            headers = {"WWW-Authenticate":"Bearer"},
        )'''
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400,detail="Inactive user")
    return current_user 

@app.post("/token",response_model = Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    #user_dict = fake_users_db.get(form_data.username)
    #user = UserInDB(**user_dict)
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail = "Incorrect username or password",headers = {"WWW-Authenticate":"Bearer"},)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data = {"sub":user.username},expires_delta=access_token_expires
    )
    '''hashed_password = fake_hash_password(form_data.password)
    if not hashed_password==user.hashed_password:
        raise HTTPException(status_code=400, detail = "Incorrect username or password")''' 
    return {"access_token": access_token, "token_type":"bearer"}

#Inject the current user
@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("users/me/items")
async def read_own_items(current_user: User=Depends(get_current_active_user)):
    return [{"item_id":"Foo","owner":current_user.username}]