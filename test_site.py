from fastapi import FastAPI
import uvicorn

app = FastAPI(title="Site vulnérable de test")

@app.get("/")
def home():
    return {"message": "Bienvenue sur le site test protégé par WAF"}

@app.get("/page/{id}")
def page(id: str):
    return {"page": id, "contenu": "Ceci est une page normale"}

@app.get("/admin")
def admin():
    return {"secret": "zone admin (à protéger)"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9001)