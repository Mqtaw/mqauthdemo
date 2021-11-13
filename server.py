import hmac
import hashlib
import base64
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "1e1dc9c447b0e957fc9b47988a2d9979ffc7ead432ee9387faa0b0236e705953"
PASSWORD_SALT = "975223dd7427803e32290bef61ae71c75e3b153c8ba023ac526a268df408ee1d"

# some_password_1
users = {
    'Nik': {
        "name": 'Ник',
        "password": "ae471ba1b2480f77feac70a15289008db1a585e81257094c16c4ac8da98ed977",
        "balance": 800_000
    },
    "Maks": {
        "name": 'Макс',
        "password": "6c20c034f78503b75c1d05cd89f4eef0ffa2ae120817d3901a573d67d64422e6",
        "balance": 200_000
    }
}


def verify_password(password: str, password_hash: str) -> bool:
    return hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower() \
    == password_hash.lower()


def sign_data(data: str) -> str:
    """Возвращает подписанные данные"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("templates/login.html", 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет: {users[valid_username]['name']}!<br>"
        f"Ваш баланс: {users[valid_username]['balance']}"
        , media_type='text/html')


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(password, user["password"]):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю"
            }),
            media_type='application/json')

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Уважаемый: {user['name']}<br>Ваш баланс: {user['balance']}"
        }),
        media_type='application/json')
    
    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed, expires=600)
    return response