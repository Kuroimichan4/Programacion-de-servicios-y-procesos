# jwt es una forma segura de transmitir información entre partes como un objeto JSON. Es un una cadena de texto que contiene datos codificados y firmados digitalmente con fecha de expiración.
import os # el os es un módilo que porporciona una manera de interactuar con el sistema operativo. Es para manejar variables de entorno. Sirve para no dejar datos sensibles en el código.

from fastapi import FastAPI, HTTPException, Depends # estos son los módulos principales de FastAPI, que son necesarios para crearla. Esto dice: Del módulo fastapi, importa la clase FastAPI, y otras cosas necesarias para manejar excepciones HTTP y dependencias.
from fastapi.security import OAuth2PasswordBearer # este módulo es para manejar la autenticación OAuth2 con tokens
from jose import JWTError, jwt # jose es una biblioteca para manejar JSON Web Tokens (JWT)
from datetime import datetime, timedelta # estos módulos son para manejar fechas y tiempos
from fastapi.middleware.cors import CORSMiddleware # este módulo es para manejar CORS (Cross-Origin Resource Sharing)



# Constantes que contienen la clave secreta y configuración del token
# SECRET_KEY = "secreto_muy_seguro"  Sustituyo esto por una variable de entorno de windows. la llamaré x
SECRET_KEY = os.getenv("x") # el metodo getenv busca dentro de las variables de entorno con el nombre que le demos y su contenido
if not SECRET_KEY:
    raise ValueError("Variable de entorno no encontrada ¡ESPAVILA!")
ALGORITHM = "HS256" # algoritmo criptográfico utilizado para la firma del token. HS256 es un algoritmo simétrico que utiliza una clave secreta compartida para firmar y verificar el token
ACCESS_TOKEN_EXPIRE_MINUTES = 5

app = FastAPI() # FastAPI es una clase que representa la aplicación web. Esto crcea la instancia de la aplicación FastAPI. 
# Así que cada vez que ponga app. estoy trabajando con esta aplicación web.

# Habilitar CORS para evitar problemas de conexión
#  el middleware  Es como un filtro que puede modificar las solicitudes y respuestas. Es un componente que se ejecuta entre la solicitud del cliente y la respuesta del servidor.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["null"],      # Quién puede acceder. Al poner null es para que al hacer doble click al archivo html, lo permita. http://localhost:5500 live server y http://localhost:8000 fastapi
    allow_credentials=True,   # Si se permiten cookies/credenciales
    allow_methods=["GET", "POST"],      # Qué métodos HTTP se permite. Luego ver si lo cambio a ["GET", "POST", "PUT", "DELETE"]
    allow_headers=["*"],      # Qué cabeceras se permiten. Los headers son metadatos que se envían junto con la solicitud o respuesta HTTP. Sin ellos, el servidor podría rechazar la solicitud por razones de seguridad.   
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # esto es el esquema de seguridad OAuth2 que usaremos para proteger nuestros endpoints con tokens

# Función para crear un token JWT
def create_jwt(data: dict, expires_delta: timedelta): # data dictes un diccionario con los datos del usuario y expires_delta el tiempo que dura
    to_encode = data.copy() # copia el diccionario para no modificar el original en to_encode
    expire = datetime.utcnow() + expires_delta # calcula la fecha y hora de expiración
    to_encode.update({"exp": expire}) # actualiza to_encode y le añade expire que es la fecha de caducidad al diccionario
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) # llama a la librería de jwt para codificar el diccionario con la info dada

# ENDPOINT para obtener un token (simulación de login). Cada vez que se le haga una petición POST a /token, se generará un token JWT.
@app.post("/token") 
async def login(): #nombre de la función dentro del endpoint simplemente
    user_data = {"sub": "usuario123"}  # Simulación de usuario autenticado (se usa sub de forma estándar para representar la identidad del user)
    token = create_jwt(user_data, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)) #llama a la función de antes para obtener el token
    return {"access_token": token, "token_type": "bearer"} # retornará el token y el tipo de token que en este caso es bearer sea lo que sea

# ENDPOINT protegido que requiere un JWT válido
@app.get("/protected")
async def protected(token: str = Depends(oauth2_scheme)): #  Depends(oauth2_scheme): función de fastAPI que extrae el token del encabezado de la solicitud y lo pasa como argumento
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) # payload ahora contiene los datos del usuario/token/tiempo
        return {"message": "Acceso permitido", "user": payload["sub"]}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    

# Para ejecutar la aplicación, he usado estos comandos en la termional: 
# crear el entorno virtual:
# py -m venv venv
# activar el entorno virtual:
# venv\Scripts\activate
# instalar las librerías necesarias:
# pip install uvicorn fastapi
# pip install python-jose
# poner en marcha: 
# python -m uvicorn main:app --reload

# contra para la máquina virtual de kali: kali, kali

# python.exe -m pip install --upgrade pip

# from core.security import create_jwt, verify_jwt
