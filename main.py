from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession 
from sqlalchemy.orm import sessionmaker, declarative_base 
from sqlalchemy import Column, Integer, String 
from pydantic import BaseModel 
from jose import jwt, JWTError 
from azure.storage.blob import BlobServiceClient 
from azure.identity import DefaultAzureCredential 
from azure.keyvault.secrets import SecretClient 
from passlib.context import CryptContext 
from datetime import datetime, timedelta
import logging
import pyodbc 
import uvicorn



# === Logging Configuration ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === App Configuration ===
app = FastAPI(title="Link Up API", version="1.0.0")



# code front-end
from fastapi.middleware.cors import CORSMiddleware

# Ajouter le middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Ou spécifiez les domaines autorisés : ["http://localhost:3000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
#end 

# === Azure Key Vault Configuration ===
KEY_VAULT_NAME = "keyazureproject1"
KEY_VAULT_URL = f"https://{KEY_VAULT_NAME}.vault.azure.net"

try:
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
    SECRET_KEY = secret_client.get_secret("codeprojet").value
except Exception as e:
    logger.error(f"Failed to authenticate with Azure Key Vault: {e}")
    SECRET_KEY = "fallback-secret-key"  # Use a secure fallback in production

ALGORITHM = "HS256"

# === Password Hashing Configuration ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# === JWT Token Functions ===
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=1))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# === Database Configuration (Azure SQL with pyodbc) ===
server = 'serverproject.database.windows.net'
database = 'azuredata'
username = 'adminHEF'
password = 'Hela_elda_fanta'

connection_string = f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}'

def get_db_connection():
    try:
        conn = pyodbc.connect(connection_string)
        return conn
    except pyodbc.Error as e:
        logger.error(f"Database connection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database connection failed: {e}")

# === Azure Blob Storage Configuration ===
AZURE_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=azureproject1234593f5;AccountKey=05RjPkjKGJqPD1Cs/9okD8IRFZhFfZhvg/APfyNpcwDfGzC263xzcNF7X26Abu8So+cTdW/Ise9u+ASthaWECw==;EndpointSuffix=core.windows.net"
CONTAINER_NAME = "containerapp1"

def upload_to_blob(file: UploadFile):
    try:
        blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=file.filename)
        blob_client.upload_blob(file.file, overwrite=True)
        return f"https://{blob_service_client.account_name}.blob.core.windows.net/{CONTAINER_NAME}/{file.filename}"
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {e}")

# === Models ===
class UserCreate(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True
# === API ===
# === Routes ===
@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Vérifier si l'utilisateur existe déjà
        select_query = "SELECT * FROM Utilisateur WHERE email = ?"
        cursor.execute(select_query, user.email)
        existing_user = cursor.fetchone()

        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        # Insérer l'utilisateur
        hashed_password = hash_password(user.password)
        insert_query = "INSERT INTO Utilisateur (email, mot_de_passe) VALUES (?, ?)"
        cursor.execute(insert_query, user.email, hashed_password)
        conn.commit()

        # code de base
        return UserResponse(id=cursor.lastrowid, email=user.email)
        #cursor.execute("SELECT SCOPE_IDENTITY()")
        #new_user_id = cursor.fetchone()[0]
        #return UserResponse(id=new_user_id, email=user.email)

        # recuperation de donnees sans user register
        #return UserResponse(id=1, email="test@user.com")

        

    except pyodbc.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    finally:
        conn.close()

@app.get("/users")
def get_users():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        select_query = "SELECT id, email FROM Utilisateur"
        cursor.execute(select_query)
        rows = cursor.fetchall()

        users = [{"id": row[0], "email": row[1]} for row in rows]
        return users

    except pyodbc.Error as e:
        #code etranger
        logger.error(f"Database error: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    finally:
        conn.close()

@app.post("/upload")
async def upload_media(file: UploadFile = File(...)):
    file_url = upload_to_blob(file)
    return {"url": file_url}

# === Startup Event ===
@app.on_event("startup")
async def startup():
    logger.info("Starting up the application...")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Create table if not exists
        create_table_query = """
        CREATE TABLE IF NOT EXISTS Utilisateur (
            id INT IDENTITY(1,1) PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            mot_de_passe VARCHAR(255) NOT NULL
        );
        """
        cursor.execute(create_table_query)
        conn.commit()
    except pyodbc.Error as e:
        logger.error(f"Failed to create table: {e}")
    finally:
        conn.close()
    logger.info("Database table setup completed.")

# === Main Entry Point ===
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
