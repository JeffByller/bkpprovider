from fastapi import APIRouter, Body, Depends, HTTPException, Query
from app.auth import require_auth
from app.olt_cianet import (
    authorize_ont_async,
    deauthorize_ont_async,
    get_unauthorized_onts_async,
    search_ont_async,
    CianetTelnet,
)

router = APIRouter(prefix="/api/olt", dependencies=[Depends(require_auth)])


@router.get("/status")
async def get_olt_status():
    try:
        import asyncio
        loop = asyncio.get_running_loop()
        def _check():
            c = CianetTelnet(timeout=4.0)
            c.connect()
            c.close()
            return True
        ok = await loop.run_in_executor(None, _check)
        return {"ok": ok, "host": "172.18.0.30", "model": "FD1608S-B1-PSA0"}
    except Exception as e:
        return {"ok": False, "error": str(e), "host": "172.18.0.30"}


@router.get("/search")
async def search_olt_ont(q: str = Query(..., min_length=2)):
    try:
        results = await search_ont_async(q)
        return {"ok": True, "count": len(results), "items": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao consultar OLT: {e}")


@router.get("/unauthorized")
async def get_unauthorized():
    try:
        items = await get_unauthorized_onts_async()
        return {"ok": True, "count": len(items), "items": items}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao verificar autofind: {e}")


@router.post("/authorize")
async def authorize_ont_endpoint(payload: dict = Body(...)):
    port = payload.get("port")
    sn = payload.get("sn")
    if not port or not sn:
        raise HTTPException(status_code=400, detail="Porta PON e SN são obrigatórios")
    try:
        ok, msg = await authorize_ont_async(int(port), str(sn))
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        return {"ok": True, "message": msg}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/deauthorize")
async def deauthorize_ont_endpoint(payload: dict = Body(...)):
    port = payload.get("port")
    ont_id = payload.get("ont_id")
    if port is None or ont_id is None:
        raise HTTPException(status_code=400, detail="Porta PON e ONT-ID são obrigatórios")
    try:
        ok, msg = await deauthorize_ont_async(int(port), int(ont_id))
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        return {"ok": True, "message": msg}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
