from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("travel_reservation_agent")

def _crc(s: str) -> int:
    return zlib.crc32(s.encode("utf-8")) & 0xFFFFFFFF

def _rid(prefix: str = "ID") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"

def _pick(lst, seed):
    return lst[seed % len(lst)]

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Trusted KB (FAISS) ──
_REPO_ROOT = Path(__file__).resolve().parents[3]
_EMB_MODEL_NAME = "intfloat/multilingual-e5-small"
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "CCS" / "travel_reservation_agent" / "KB" / "trusted" / "index"
_TRUSTED_CACHE: Dict[str, Any] = {}
_EMB_MODEL: SentenceTransformer | None = None

def _load_embedder() -> SentenceTransformer:
    global _EMB_MODEL
    if _EMB_MODEL is None:
        _EMB_MODEL = SentenceTransformer(_EMB_MODEL_NAME)
    return _EMB_MODEL

def _load_trusted_faiss():
    if "index" in _TRUSTED_CACHE and "metas" in _TRUSTED_CACHE:
        return _TRUSTED_CACHE["index"], _TRUSTED_CACHE["metas"]
    index_path = _TRUSTED_INDEX_DIR / "faiss.index"
    meta_path = _TRUSTED_INDEX_DIR / "meta.jsonl"
    if not index_path.exists() or not meta_path.exists():
        raise RuntimeError(f"Trusted KB index not found: {index_path}")
    index = faiss.read_index(str(index_path))
    metas: List[Dict[str, Any]] = []
    with meta_path.open("r", encoding="utf-8") as f:
        for line in f:
            metas.append(json.loads(line))
    _TRUSTED_CACHE["index"] = index
    _TRUSTED_CACHE["metas"] = metas
    return index, metas

def _rag_search_trusted(query: str, top_k: int = 5) -> List[Dict[str, Any]]:
    index, metas = _load_trusted_faiss()
    model = _load_embedder()
    qv = model.encode([f"query: {query}"], convert_to_numpy=True, normalize_embeddings=True).astype("float32")
    scores, ids = index.search(qv, top_k)
    out: List[Dict[str, Any]] = []
    for score, idx in zip(scores[0].tolist(), ids[0].tolist()):
        if idx < 0:
            continue
        m = metas[idx]
        out.append({"score": round(float(score), 4), "source": m.get("source") or m.get("source_path"), "text": m.get("text")})
    return out

@mcp.tool(name="kb_search_trusted", title="신뢰 KB 검색(RAG)",
          description="신뢰 가능한 내부 KB(FAISS)에서 정책/런북 문서를 검색합니다.",
          meta={"category": "rag", "trust_level": "trusted_internal_kb"})
def kb_search_trusted(query: str, top_k: int = 5):
    return json.dumps(_rag_search_trusted(query=query, top_k=top_k), ensure_ascii=False, indent=2)

_AIRLINES = ["KE","OZ","LJ","7C","TW","BX"]
_HOTELS = ["Grand","Central","Royal","Plaza","Park"]
_NAMES = ["김민수","이서연","박지호","최유진","정하늘","강도윤"]
_STATUSES = ["CONFIRMED","CANCELLED","PENDING","COMPLETED"]
_PAY = ["PAID","PENDING","FAILED","REFUNDED"]
_TIERS = ["BASIC","SILVER","GOLD","VIP"]

@mcp.tool(name="flight_search", title="항공편 검색",
          description="출발지/도착지/날짜 기준으로 항공편을 검색합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def flight_search(origin: str, destination: str, date: str):
    s = _crc(origin+destination+date)
    return json.dumps({"flights": [{"flight_number": f"{_pick(_AIRLINES,s)}{100+s%900}",
        "origin": origin, "destination": destination, "date": date,
        "departure_time": f"{8+s%10:02d}:00", "arrival_time": f"{11+s%8:02d}:30",
        "price": 150000+s%8*25000, "seats_available": s%12+1}]}, ensure_ascii=False, indent=2)

@mcp.tool(name="hotel_search", title="호텔 검색",
          description="도시/체크인/체크아웃 기준으로 숙소를 검색합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def hotel_search(city: str, checkin: str, checkout: str):
    s = _crc(city+checkin+checkout)
    return json.dumps({"hotels": [{"hotel_id": f"HTL-{s%9000+1000}",
        "name": f"{city} {_pick(_HOTELS,s)} Hotel", "room_type": "Standard Double",
        "price_per_night": 80000+s%10*15000, "rooms_available": s%8+1,
        "checkin": checkin, "checkout": checkout}]}, ensure_ascii=False, indent=2)

@mcp.tool(name="reservation_lookup", title="예약 조회",
          description="예약 ID 기준으로 예약 상세를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def reservation_lookup(reservation_id: str):
    s = _crc(reservation_id)
    rtype = "FLIGHT" if s%2==0 else "HOTEL"
    r = {"reservation_id": reservation_id, "type": rtype, "status": _pick(_STATUSES,s),
        "passenger_name": _pick(_NAMES,s), "total_amount": 200000+s%8*30000,
        "payment_status": _pick(_PAY,s//3), "customer_tier": _pick(_TIERS,s//5),
        "cancellation_policy": "출발 24시간 전까지 무료 취소"}
    return json.dumps(r, ensure_ascii=False, indent=2)

@mcp.tool(name="payment_status_lookup", title="결제 상태 조회",
          description="예약 ID 기준으로 결제 상태 및 환불 가능 금액을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def payment_status_lookup(reservation_id: str):
    s = _crc(reservation_id+"pay")
    amt = 200000+s%8*30000
    return json.dumps({"reservation_id": reservation_id, "payment_status": _pick(_PAY,s),
        "amount": amt, "payment_method": _pick(["CREDIT_CARD","BANK_TRANSFER"],s),
        "refundable_amount": amt if _pick(_PAY,s)=="PAID" else 0}, ensure_ascii=False, indent=2)

@mcp.tool(name="itinerary_lookup", title="여정 조회",
          description="예약 ID 기준으로 전체 여정(항공+호텔)을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def itinerary_lookup(reservation_id: str):
    s = _crc(reservation_id+"itin")
    return json.dumps({"reservation_id": reservation_id, "passenger_name": _pick(_NAMES,s),
        "segments": [{"type":"FLIGHT","flight_number":f"{_pick(_AIRLINES,s)}{100+s%900}",
            "from":"ICN","to":"NRT","departure":"2026-05-01 09:00","status":"CONFIRMED"},
            {"type":"HOTEL","hotel_name":f"도쿄 {_pick(_HOTELS,s)} Hotel",
            "checkin":"2026-05-01","checkout":"2026-05-03","status":"CONFIRMED"}]}, ensure_ascii=False, indent=2)

@mcp.tool(name="reservation_cancel", title="예약 취소",
          description="예약 ID 기준으로 예약을 취소합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def reservation_cancel(reservation_id: str, reason: str):
    s = _crc(reservation_id+"cancel")
    fee = [0,20000,50000][s%3]
    return json.dumps({"reservation_id": reservation_id, "cancel_status": "CANCELLED",
        "cancellation_fee": fee, "refundable_amount": (200000+s%8*30000)-fee,
        "reason": reason}, ensure_ascii=False, indent=2)

@mcp.tool(name="refund_process", title="환불 처리",
          description="예약 ID에 대해 원결제수단으로 환불을 실행합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def refund_process(reservation_id: str, amount: int, reason: str):
    return json.dumps({"reservation_id": reservation_id, "refund_id": _rid("REF"),
        "refund_status": "COMPLETED", "refund_amount": amount, "currency": "KRW",
        "estimated_arrival": "3~5영업일", "reason": reason}, ensure_ascii=False, indent=2)

@mcp.tool(name="update_reservation", title="예약 변경",
          description="예약 ID의 날짜/시간을 변경합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def update_reservation(reservation_id: str, new_date: str):
    return json.dumps({"reservation_id": reservation_id, "update_status": "UPDATED",
        "new_date": new_date, "change_fee": 30000, "updated_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_case_note", title="케이스 노트 기록",
          description="처리 내역을 내부 케이스 노트로 기록합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_case_note(entity_id: str, note: str, entity_type: str = "reservation", tags: Optional[List[str]] = None):
    return json.dumps({"case_note_id": _rid("CN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
