# app/main.py 

from fastapi import FastAPI
from app.api.routers import test_connection  # Ensure this is correct

app = FastAPI()

@app.get("/")
async def read_root():
    return {"message": "Welcome to the API!"}

# Include the router for the test connection
app.include_router(test_connection.router)

@app.on_event("startup")
async def startup():
    print("Connecting to Supabase...")

@app.on_event("shutdown")
async def shutdown():
    print("Disconnecting from Supabase...")
