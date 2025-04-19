from fastapi import FastAPI
from routes.router import router as main_router
from fastapi.middleware.cors import CORSMiddleware
from routes.post_router import router as post_router


app = FastAPI(
    title="FastAPI Google Auth Example",
    description="Backend for authenticating with Google using OAuth2",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://techtuners-tt.github.io"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register main router (includes auth)
app.include_router(main_router)
app.include_router(post_router)

@app.get("/")
def root():
    return {"message": "Welcome to the FastAPI Google Auth API. Go to /auth/login to start authentication."}
