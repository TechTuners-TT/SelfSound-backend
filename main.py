from fastapi import FastAPI
from routes.router import router as main_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SelfSound",
    description="Backend for SelfSound",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://techtuners-tt.github.io/frontend/#/"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(main_router)

@app.get("/")
def root():
    return {"message": "Welcome to the FastAPI Google Auth API. Go to /auth/login to start authentication."}
