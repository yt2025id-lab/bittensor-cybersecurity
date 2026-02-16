from fastapi import FastAPI
from cyber.routes import router as cyber_router

app = FastAPI(title="AI Cybersecurity Network Subnet")
app.include_router(cyber_router)

@app.get("/")
def root():
    return {"message": "Welcome to the AI Cybersecurity Network Subnet powered by Bittensor!"}
