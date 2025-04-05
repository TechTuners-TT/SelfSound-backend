from fastapi import FastAPI
from routes.router import router as main_router

app = FastAPI(
    title="FastAPI Google Auth Example",
    description="Backend for authenticating with Google using OAuth2",
    version="1.0.0",
)

# Register main router (includes auth)
app.include_router(main_router)

@app.get("/")
def root():
    return {"message": "Welcome to the FastAPI Google Auth API. Go to /auth/login to start authentication."}
