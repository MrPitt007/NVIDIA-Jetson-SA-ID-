"""SA-ID Payment API — v1"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional
from app.core.auth import require_auth
from app.services.payment_service import PaymentService, PaymentMethod

router = APIRouter()
_svc   = PaymentService()


class PayRequest(BaseModel):
    amount_zar:  float       = Field(..., gt=0, le=10_000_000)
    method:      PaymentMethod
    merchant_id: str         = Field(..., min_length=4, max_length=64)
    terminal_id: str         = Field(..., min_length=4, max_length=64)
    id_number:   str         = Field(..., min_length=13, max_length=13)
    id_verified: bool        = False


class FinaliseRequest(BaseModel):
    tx_id:    str
    approved: bool
    sarb_ref: Optional[str] = None


@router.post("/initiate")
async def initiate_payment(req: PayRequest, payload: dict = Depends(require_auth)):
    try:
        tx = await _svc.initiate(
            amount_zar  = req.amount_zar,
            method      = req.method,
            merchant_id = req.merchant_id,
            terminal_id = req.terminal_id,
            client_type = payload["client_type"],
            id_number   = req.id_number,
            id_verified = req.id_verified,
        )
        return {"tx_id": tx.tx_id, "status": tx.status, "amount_zar": tx.amount_zar}
    except PermissionError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e))


@router.post("/finalise")
async def finalise_payment(req: FinaliseRequest, payload: dict = Depends(require_auth)):
    try:
        return await _svc.finalise(req.tx_id, req.approved, req.sarb_ref or "")
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))


@router.post("/submit")
async def submit_to_sarb(tx_id: str, payload: dict = Depends(require_auth)):
    try:
        return await _svc.submit_to_sarb(tx_id)
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
