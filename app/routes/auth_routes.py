from fastapi import APIRouter, Cookie, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import (
    check_password, clear_attempts, create_session, destroy_session,
    is_locked_out, register_failed_attempt,
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/login")
async def login_page(request: Request, error: str = None):
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/login")
async def login_submit(request: Request, password: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"

    locked, remaining = is_locked_out(client_ip)
    if locked:
        return RedirectResponse(
            url=f"/login?error=Muitas+tentativas.+Aguarde+{remaining}+segundos.", status_code=303
        )

    if check_password(password):
        clear_attempts(client_ip)
        token = create_session()
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key="session_token", value=token, httponly=True, samesite="lax", secure=True)
        return response

    register_failed_attempt(client_ip)
    return RedirectResponse(url="/login?error=Senha+Incorreta!", status_code=303)


@router.get("/logout")
async def logout(session_token: str = Cookie(None)):
    destroy_session(session_token)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="session_token")
    return response
