from fastapi import FastAPI
import uvicorn

import contacts, auth

app = FastAPI()

app.include_router(auth.app, prefix='/api')
app.include_router(contacts.app, prefix="/api")


@app.get('/')
def read_root():
    return {'message': "Contact manager API"}


if __name__ == '__main__':
    uvicorn.run(
        app='main:app',
        host='0.0.0.0',
        port=8000,
        reload=True
    )
