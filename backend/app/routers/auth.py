# app/routers/auth.py
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime, timedelta
import jwt
from ..config import settings
from firebase_admin import auth, firestore
import requests
from google.cloud import firestore as google_firestore
from ..services.firebase_service import FirebaseService
from ..schemas.user import UserLogin, UserCreate, TokenResponse
from ..utils.validators import validate_phone, validate_email

router = APIRouter()
security = HTTPBearer()

# --- Helper Functions ---

def create_access_token(data: Dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(data: Dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    
# --- Endpoints ---

@router.post("/register", response_model=Dict[str, Any])
async def register(user_data: UserCreate):
    try:
        # 1. Role Logic
        role = user_data.role
        if user_data.email.endswith('@afyadirecttanzania.com'):
            role = 'admin'
        
        # 2. Create in Firebase Auth & Firestore Users Collection
        user_id = await FirebaseService.create_user(
            email=user_data.email,
            password=user_data.password,
            user_data={
                'fullName': user_data.full_name,
                'phone': user_data.phone,
                'role': role,
                'language': user_data.language,
                'isActive': True
            }
        )
        
        # 3. Create Role-Specific Profile Documents
        db = FirebaseService.get_db()
        if role == 'patient':
            db.collection('patients').document(user_id).set({
                'userId': user_id,
                'dateOfBirth': user_data.date_of_birth,
                'bloodGroup': user_data.blood_group,
                'allergies': user_data.allergies,
                'createdAt': google_firestore.SERVER_TIMESTAMP
            })
        elif role == 'doctor':
            db.collection('doctors').document(user_id).set({
                'userId': user_id,
                'specialty': user_data.specialty,
                'licenseNumber': user_data.license_number,
                'consultationFee': user_data.consultation_fee,
                'isVerified': False,
                'rating': 0,
                'createdAt': google_firestore.SERVER_TIMESTAMP
            })
        
        return {
            "message": "User registered successfully",
            "user_id": user_id,
            "role": role
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login", response_model=Dict[str, Any])
async def login(credentials: UserLogin):
    # 1. Verify Email/Password with Google REST API
    verify_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={settings.FIREBASE_WEB_API_KEY}"
    payload = {"email": credentials.email, "password": credentials.password, "returnSecureToken": True}
    
    response = requests.post(verify_url, json=payload)
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    res_data = response.json()
    uid = res_data['localId']

    # 2. Fetch Profile from Firestore
    user_data = await FirebaseService.get_user(uid)
    if not user_data:
        raise HTTPException(status_code=404, detail="User record not found")

    # 3. Generate Backend JWT
    access_token = create_access_token({"sub": uid, "role": user_data.get('role')})
    
    # 4. Update Last Login
    await FirebaseService.update_user(uid, {'lastLogin': google_firestore.SERVER_TIMESTAMP})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": uid,
        "role": user_data.get('role'),
        "full_name": user_data.get('fullName')
    }




class GoogleLogin(BaseModel):
    token: str


@router.post("/google", response_model=Dict[str, Any])
async def google_login(payload: GoogleLogin):
    try:
        decoded_token = auth.verify_id_token(payload.token)
        uid = decoded_token.get('uid')
        if not uid:
            raise HTTPException(status_code=401, detail='Invalid Google token')

        user_data = await FirebaseService.get_user(uid)
        if not user_data:
            firebase_user = auth.get_user(uid)
            full_name = firebase_user.display_name or 'Afya Patient'
            email = firebase_user.email or ''
            user_data = {
                'uid': uid,
                'fullName': full_name,
                'email': email,
                'phone': firebase_user.phone_number or '',
                'role': 'patient',
                'language': 'en',
                'isActive': True,
                'createdAt': google_firestore.SERVER_TIMESTAMP,
                'updatedAt': google_firestore.SERVER_TIMESTAMP,
                'fcmToken': '',
                'profileImage': '',
            }
            FirebaseService.get_db().collection('users').document(uid).set(user_data)
            FirebaseService.get_db().collection('patients').document(uid).set({
                'userId': uid,
                'dateOfBirth': None,
                'address': '',
                'bloodGroup': '',
                'allergies': '',
                'medicalHistory': '',
                'emergencyContact': '',
                'insuranceInfo': '',
                'createdAt': google_firestore.SERVER_TIMESTAMP
            })
        else:
            full_name = user_data.get('fullName')

        return {
            'role': user_data.get('role', 'patient'),
            'user_id': uid,
            'full_name': full_name
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=f'Google authentication failed: {e}')


@router.post("/refresh")
async def refresh_token(refresh_token: str):
    """Refresh access token"""
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_data = await FirebaseService.get_user(user_id)
        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")
        
        new_access_token = create_access_token({
            "sub": user_id,
            "role": user_data.get('role')
        })
        
        return {"access_token": new_access_token}
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@router.post("/logout")
async def logout(payload: Dict = Depends(verify_token)):
    """Logout user"""
    # In production, add token to blacklist
    return {"message": "Logged out successfully"}

@router.post("/reset-password")
async def reset_password(email: str):
    """Send password reset email"""
    try:
        auth.generate_password_reset_link(email)
        return {"message": "Password reset email sent"}
    except Exception as e:
        raise HTTPException(status_code=404, detail="User not found")