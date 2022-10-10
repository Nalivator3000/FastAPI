from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from router import blog_get
from router import blog_post
from router import user, article, product, file
from db.database import engine
from db import models
from router.exceptions import StoryException
from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse
from auth import authentication
from fastapi.staticfiles import StaticFiles
from templates import templates
import time
from client import html
from fastapi.websockets import WebSocket


app = FastAPI()
app.include_router(authentication.router)
app.include_router(file.router)
app.include_router(article.router)
app.include_router(product.router)
app.include_router(user.router)
app.include_router(blog_get.router)
app.include_router(blog_post.router)
app.include_router(templates.router)


@app.get('/hello')
def index():
    return {'message': 'Hello world!'}


@app.exception_handler(StoryException)
def story_exception_handler(request: Request, exc: StoryException):
    return JSONResponse(
        status_code=418,
        content={'detail': exc.name}
    )


@app.get('/')
async def get():
    return HTMLResponse(html)


clients = []


@app.websocket('/chat')
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    while True:
        data = await websocket.receive_text()
        for client in clients:
            await client.send_text(data)


# @app.exception_handler(HTTPException)
# def custom_handler(request: Request, exc: StoryException):
#     return PlainTextResponse(str(exc), status_code=400)


models.Base.metadata.create_all(engine)


@app.middleware('http')
async def add_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    response.headers['duration'] = str(duration)
    return response


app.mount('/files', StaticFiles(directory='files'), name='files')
app.mount('/templates/static', StaticFiles(directory='templates/static'), name='static')
