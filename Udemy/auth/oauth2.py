from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from fastapi import HTTPException, status
from fastapi.param_functions import Depends
from fastapi.security import OAuth2PasswordBearer

from jose import jwt
from jose.exceptions import JWTError

from db import db_user
from db.database import get_db

oauth2_schema = OAuth2PasswordBearer(tokenUrl='token')

SECRET_KEY = '3e6fad5bab0a03b2625bdd26f2d4b97995b276ef7723fd1a1747af05e43cc12b'
ALGORYTHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORYTHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_schema), db: Session = Depends(get_db)):
    credentials_exceptions = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORYTHM])
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exceptions
    except JWTError:
        raise credentials_exceptions

    user = db_user.get_user_by_username(db, username)

    if user is None:
        raise credentials_exceptions

    return user
