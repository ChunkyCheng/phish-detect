import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="src/templates")

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8001")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request, name="checker_page.html", context={"backend_url": BACKEND_URL}
    )
