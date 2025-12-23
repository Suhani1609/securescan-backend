from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.db.mongo import user_collection
from app.services.auth_utils import hash_password, verify_password, create_access_token

router = APIRouter()

class UserAuth(BaseModel):
    email: str
    password: str

@router.post("/signup")
def signup(user: UserAuth):
    try:
        existing = user_collection.find_one({"email": user.email})
        if existing:
            raise HTTPException(status_code=400, detail="User already exists")

        hashed_password = hash_password(user.password)

        user_collection.insert_one({
            "email": user.email,
            "password": hashed_password
        })

        return {"message": "User registered successfully"}

    except Exception as e:
        print("SIGNUP ERROR:", e)
        raise HTTPException(status_code=500, detail="Signup failed")


@router.post("/login")
def login(user: UserAuth):
    db_user = user_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user.email})

    return {
        "access_token": token,
        "token_type": "bearer"
    }
