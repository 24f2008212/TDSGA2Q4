
import logging

import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-eg85ypke.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


class VerifyRequest(BaseModel):
    token: str


@app.post("/verify")
async def verify_token(body: VerifyRequest):
    try:
        claims = jwt.decode(
            body.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud"],
            },
        )

        # Return the original claims without changing their types.
        if "email" not in claims or "sub" not in claims:
            logger.warning("Validly signed token lacks email or sub")
            return JSONResponse(
                status_code=401,
                content={"valid": False},
            )

        return {
            "valid": True,
            "email": claims["email"],
            "sub": claims["sub"],
            "aud": claims["aud"],
        }

    except jwt.InvalidTokenError as exc:
        # The exception message appears in Render logs.
        logger.warning(
            "JWT verification failed: %s: %s",
            type(exc).__name__,
            str(exc),
        )
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )


@app.get("/")
async def root():
    return {"status": "ok"}
