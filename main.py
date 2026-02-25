from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from cyber.routes import router as cyber_router

app = FastAPI(title="AI Cybersecurity Network Subnet", docs_url="/docs")

# API routes
app.include_router(cyber_router)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def root():
    return FileResponse("static/index.html")
