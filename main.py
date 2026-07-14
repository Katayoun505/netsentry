from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import Base, engine
import auth
import user
import logs
import alerts
import monitoring


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="NetSentry",
    description="Network traffic monitoring and threat detection system",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(monitoring.router)


@app.get("/")
def root():
    return {"status": "NetSentry API running"}