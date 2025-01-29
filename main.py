from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import ForeignKey, create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import bcrypt
from sqlalchemy.orm import relationship
from fastapi import File, UploadFile
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer


SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(DATABASE_URL)
db_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
db = db_session()

origins = [
    "http://127.0.0.1:5500",
    "http://127.0.0.1:8000",
]

app.mount("/files", StaticFiles(directory="instance"), name="files")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    user_name = Column(String, unique=True, index=True)
    age = Column(Integer)
    password = Column(String)

    def password_hash(self, password):
        self.password = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)  


class UserFile(Base):
    __tablename__ = "files"
    file_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    file_name = Column(String, index=True)


    user = relationship("User", back_populates="files")

    User.files = relationship("UserFile", back_populates="user")

Base.metadata.create_all(bind=engine)

def get_db():
    db = db_session()
    try:
        yield db
    finally:
        db.close()



# @app.post("/login")
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         user_name: str = payload.get("sub")
#         if user_name is None:
#             raise credentials_exception
#     except JWTError:
#         raise credentials_exception
#     user = db.query(User).filter(User.user_name == user_name).first()
#     if user is None:
#         raise credentials_exception
#     return user

@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    user_name = data["user_name"]
    password = data["password"]
    user = db.query(User).filter(User.user_name == user_name).first()
    if user:
        if user.verify_password(password):
            access_token = create_access_token(data={"sub": user_name})
            return JSONResponse(content={"access_token": access_token}, status_code=200)
        return {"message": "Invalid Password"}

@app.get("/protected-route")
async def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.user_name}"}
   

@app.get("/") 
def home():
    return {"message": "Hello World"}

@app.post("/create")
async def add_user(request: Request):
    data = await request.json()
    user_name = data["user_name"]
    password = data["password"]
    age = data["age"]
    user = User(user_name=user_name, age=age, password=password)
    user.password_hash(password)
    db.add(user)
    db.commit()
    return {"message": "User Created"}

@app.get("/read")
def read_users():
    users = db.query(User).all()
    users_to_display = [{"id": user.id, "user_name": user.user_name, "age": user.age} for user in users]
    return JSONResponse(content=users_to_display)

@app.put("/update/{id}")
async def update_user(request:Request, id):
    data = await request.json()
    user_name = data["user_name"]
    existing_user = db.query(User).filter(User.id == id).first()
    print(existing_user, id, user_name)
    if existing_user:
        existing_user.user_name = user_name
        db.commit()    
        return {"message": "User Updated"}
    return {"message": "User not found"}

@app.delete("/delete/{id}")
def delete_user(id):
    existing_user = db.query(User).filter(User.id == id).first()
    if existing_user:
        db.delete(existing_user)
        db.commit()
        return {"message": "User Deleted"}
    return {"message": "User not found"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
            file_location = f"./instance/{file.filename}"
            with open(file_location, "wb") as f:
                f.write(await file.read())
            user_id = 1  
            new_file = UserFile(user_id=user_id, file_name=file.filename)
            db.add(new_file)
            db.commit()
            
            return {"info": f"file '{file.filename}' saved at '{file_location}'"}

@app.get("/files")
def get_files():
    files = db.query(UserFile).all()
    files_to_display = [{"file_id": file.file_id, "file_name": file.file_name, "file_url": f"http://127.0.0.1:8000/files/{file.file_name}"} for file in files]
    print(files_to_display)
    return JSONResponse(content=files_to_display)
