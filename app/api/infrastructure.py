"""Altyapı örtüşmesi: IP IOC'lerinin ASN / ülke / alt ağ bazında kümelenmesi."""
from fastapi import APIRouter, Depends, HTTPException, Query

from ..db import Db, get_db
from ..security import current_user

router = APIRouter(prefix="/api/infrastructure", tags=["infrastructure"], dependencies=[Depends(current_user)])


@router.get("")
def overlap(minFamilies: int = Query(2, ge=1, le=10), db: Db = Depends(get_db)):
    summary, asns, subnets, countries = (db.query_sets("EXEC dbo.sp_InfrastructureOverlap @MinFamilies = ?, @Top = ?;", (minFamilies, 30))
                                         + [[{}], [], [], []])[:4]
    for s in subnets:
        s["IndicatorIDs"] = [int(x) for x in (s.get("IndicatorIDs") or "").split(",") if x][:50]
    return {"summary": summary[0] if summary else {}, "asns": asns, "subnets": subnets, "countries": countries}


@router.get("/indicator/{indicator_id}")
def indicator_network(indicator_id: int, db: Db = Depends(get_db)):
    info, neighbours = (db.query_sets("EXEC dbo.sp_IndicatorNetwork @IndicatorID = ?;", (indicator_id,)) + [[], []])[:2]
    if not info:
        raise HTTPException(404, "Bu IOC için ağ bilgisi yok (yalnızca IPv4 IOC'ler zenginleştirilir).")
    return {"network": info[0], "subnetNeighbours": neighbours}
