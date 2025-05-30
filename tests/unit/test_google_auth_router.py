import os
from fastapi.testclient import TestClient
from fastapi import FastAPI, HTTPException
from unittest.mock import patch
import httpx
from routes.authorization.google_auth_router import router  # Імпортуємо наш роутер
from jwt_handler import generate_jwt  # Твій генератор JWT
from datetime import datetime, timedelta

# Створюємо FastAPI додаток
app = FastAPI()

# Підключаємо маршрути до додатку
app.include_router(router)

client = TestClient(app)

# Функція для генерації реального JWT токену для тесту
def generate_test_jwt(payload: dict):
    """
    Генеруємо реальний JWT для тестування.
    """
    # Використовуємо generate_jwt для генерації токену (замість мокування)
    return generate_jwt(payload)


# Тест на відсутність параметра code в /callback
def test_callback_missing_code():
    response = client.get("/callback?state=https://techtuners-tt.github.io/frontend/#/home")
    assert response.status_code == 400
    assert response.json() == {"detail": "Authorization code is missing"}



# Тест на неправильний токен в /me/raw
def test_me_raw_invalid_token():
    response = client.get("/me/raw", cookies={"access_token": "invalid.token.string"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token"}

# Тест на відсутність токену в /me/raw
def test_me_raw_missing_token():
    response = client.get("/me/raw")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
