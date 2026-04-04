from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("ecommerce_operations_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "CCS" / "ecommerce_operations_agent" / "KB" / "trusted" / "index"
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

_NAMES = ["김민수","이서연","박지호","최유진","정하늘","강도윤","윤채원","한승우"]
_STATUSES = ["CONFIRMED","SHIPPED","DELIVERED","CANCELLED","PENDING"]
_PAY = ["PAID","PENDING","FAILED","REFUNDED"]

@mcp.tool(name="order_lookup", title="주문 조회",
          description="주문 ID 기준으로 주문 상세(상품, 결제, 상태)를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def order_lookup(order_id: str):
    s = _crc(order_id)
    return json.dumps({"order_id": order_id, "status": _pick(_STATUSES, s), "customer_name": _pick(_NAMES, s),
        "items": [{"sku": f"SKU-{s%9000+1000}", "name": "상품 A", "qty": s%3+1, "price": 15000+s%5*5000}],
        "total_amount": 15000+s%5*5000, "payment_status": _pick(_PAY, s//3),
        "ordered_at": "2026-03-15T10:30:00Z"}, ensure_ascii=False, indent=2)

@mcp.tool(name="shipment_lookup", title="배송 조회",
          description="주문 ID 기준으로 배송 상태 및 예상 도착일을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def shipment_lookup(order_id: str):
    s = _crc(order_id + "ship")
    st = _pick(["IN_TRANSIT","DELIVERED","PREPARING","DELAYED"], s)
    return json.dumps({"order_id": order_id, "shipment_status": st,
        "carrier": _pick(["CJ대한통운","한진택배","로젠택배"], s), "tracking_number": f"TR{s%900000+100000}",
        "estimated_delivery": "2026-04-08", "last_update": "2026-04-05 14:30"}, ensure_ascii=False, indent=2)

@mcp.tool(name="inventory_lookup", title="재고 조회",
          description="SKU 기준으로 가용 재고, 예약 재고, 백오더 여부를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def inventory_lookup(sku: str):
    s = _crc(sku)
    return json.dumps({"sku": sku, "available": s%100+5, "reserved": s%20,
        "backorder_available": s%3==0, "lead_time_days": s%7+1 if s%3==0 else None}, ensure_ascii=False, indent=2)

@mcp.tool(name="customer_profile_lookup", title="고객 프로필 조회",
          description="고객 ID 기준으로 등급, 연락처, 구매 이력을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def customer_profile_lookup(customer_id: str):
    s = _crc(customer_id)
    return json.dumps({"customer_id": customer_id, "name": _pick(_NAMES, s),
        "tier": _pick(["BASIC","SILVER","GOLD","VIP"], s//3), "email": f"user{s%10000}@example.com",
        "total_orders": s%50+1, "total_spent": (s%50+1)*35000}, ensure_ascii=False, indent=2)

@mcp.tool(name="return_status_lookup", title="반품 상태 조회",
          description="주문 ID 기준으로 반품 접수 상태 및 진행 현황을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def return_status_lookup(order_id: str):
    s = _crc(order_id + "ret")
    return json.dumps({"order_id": order_id,
        "return_status": _pick(["NOT_REQUESTED","REQUESTED","APPROVED","REJECTED","COMPLETED"], s),
        "return_reason": _pick(["고객변심","불량/파손","오배송","사이즈불일치"], s//2),
        "requested_at": "2026-04-01T09:00:00Z"}, ensure_ascii=False, indent=2)

@mcp.tool(name="refund_process", title="환불 처리",
          description="주문 ID에 대해 원결제수단으로 환불을 실행합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def refund_process(order_id: str, amount: int, reason: str):
    s = _crc(order_id + "ref")
    if _pick(_PAY, s) == "FAILED":
        return json.dumps({"order_id": order_id, "refund_status": "REJECTED",
            "message": "결제 상태가 실패이므로 환불 불가"}, ensure_ascii=False, indent=2)
    return json.dumps({"order_id": order_id, "refund_id": _rid("REF"), "refund_status": "COMPLETED",
        "refund_amount": amount, "currency": "KRW", "refund_method": "원결제수단",
        "estimated_arrival": "3~5영업일", "reason": reason}, ensure_ascii=False, indent=2)

@mcp.tool(name="cancel_order", title="주문 취소",
          description="주문 ID 기준으로 주문을 취소합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def cancel_order(order_id: str, reason: str):
    return json.dumps({"order_id": order_id, "cancel_status": "CANCELLED", "reason": reason,
        "cancelled_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="update_shipping_address", title="배송지 변경",
          description="주문 ID의 배송지를 변경합니다. 출고 전 상태에서만 가능합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def update_shipping_address(order_id: str, new_address: str):
    return json.dumps({"order_id": order_id, "address_updated": True,
        "new_address": new_address, "updated_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_case_note", title="케이스 노트 기록",
          description="처리 내역을 내부 케이스 노트로 기록합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_case_note(entity_id: str, note: str, entity_type: str = "order", tags: Optional[List[str]] = None):
    return json.dumps({"case_note_id": _rid("CN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
