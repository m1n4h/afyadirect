# app/routers/auth.py
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, Any
from datetime import datetime, timedelta
import jwt
from ..config import settings
from ..services.firebase_service import FirebaseService
from ..schemas.user import UserLogin, UserRegister, TokenResponse
from ..utils.validators import validate_phone, validate_email

router = APIRouter()
security = HTTPBearer()

def create_access_token(data: Dict[str, Any]) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create JWT refresh token"""
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

@router.post("/register", response_model=Dict[str, Any])
async def register(user_data: UserRegister):
    """Register a new user"""
    try:
        # Validate email format
        if not validate_email(user_data.email):
            raise HTTPException(status_code=400, detail="Invalid email format")
        
        # Validate phone number
        if not validate_phone(user_data.phone):
            raise HTTPException(status_code=400, detail="Invalid phone number")
        
        # Check if user already exists
        try:
            existing_user = auth.get_user_by_email(user_data.email)
            if existing_user:
                raise HTTPException(status_code=409, detail="Email already registered")
        except:
            pass
        
        # Determine role based on email domain for admin
        role = user_data.role
        if user_data.email.endswith('@afyadirecttanzania.com'):
            role = 'admin'
        
        # Create user in Firebase
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
        
        # Create role-specific document
        if role == 'patient':
            await FirebaseService.get_db().collection('patients').document(user_id).set({
                'userId': user_id,
                'dateOfBirth': user_data.date_of_birth,
                'bloodGroup': user_data.blood_group,
                'allergies': user_data.allergies,
                'createdAt': firestore.SERVER_TIMESTAMP
            })
        elif role == 'doctor':
            await FirebaseService.get_db().collection('doctors').document(user_id).set({
                'userId': user_id,
                'specialty': user_data.specialty,
                'licenseNumber': user_data.license_number,
                'consultationFee': user_data.consultation_fee,
                'isVerified': False,
                'rating': 0,
                'createdAt': firestore.SERVER_TIMESTAMP
            })
        
        # Create tokens
        access_token = create_access_token({"sub": user_id, "role": role})
        refresh_token = create_refresh_token({"sub": user_id})
        
        return {
            "message": "User registered successfully",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user_id,
            "role": role
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/login", response_model=Dict[str, Any])
async def login(credentials: UserLogin):
    """Login user with email and password"""
    try:
        # Get user from Firebase Auth
        try:
            user = auth.get_user_by_email(credentials.email)
        except:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Get user data from Firestore
        user_data = await FirebaseService.get_user(user.uid)
        if not user_data:
            raise HTTPException(status_code=404, detail="User data not found")
        
        if not user_data.get('isActive', True):
            raise HTTPException(status_code=403, detail="Account is disabled")
        
        # Verify admin domain
        if credentials.email.endswith('@afyadirecttanzania.com') and user_data.get('role') != 'admin':
            raise HTTPException(status_code=403, detail="Invalid admin credentials")
        
        # Create tokens
        access_token = create_access_token({
            "sub": user.uid, 
            "role": user_data.get('role')
        })
        refresh_token = create_refresh_token({"sub": user.uid})
        
        # Update last login
        await FirebaseService.update_user(user.uid, {
            'lastLogin': firestore.SERVER_TIMESTAMP
        })
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user.uid,
            "role": user_data.get('role'),
            "full_name": user_data.get('fullName')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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