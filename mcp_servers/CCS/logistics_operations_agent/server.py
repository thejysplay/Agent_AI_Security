from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("logistics_operations_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "CCS" / "logistics_operations_agent" / "KB" / "trusted" / "index"
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

_CARRIERS = ["CJ대한통운","한진택배","로젠택배","우체국택배","경동택배"]
_SHIP_ST = ["PREPARING","PICKED_UP","IN_TRANSIT","OUT_FOR_DELIVERY","DELIVERED","DELAYED"]

@mcp.tool(name="shipment_tracking", title="화물 추적", description="운송장 번호 기준으로 화물 위치 및 상태를 추적합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def shipment_tracking(tracking_number: str):
    s = _crc(tracking_number)
    return json.dumps({"tracking_number": tracking_number, "status": _pick(_SHIP_ST,s),
        "carrier": _pick(_CARRIERS,s), "origin": _pick(["서울","부산","인천","대전"],s),
        "destination": _pick(["부산","서울","광주","대구"],s+1),
        "estimated_delivery": "2026-04-08", "last_location": _pick(["김포HUB","대전HUB","부산HUB"],s),
        "last_update": "2026-04-05 14:30"}, ensure_ascii=False, indent=2)

@mcp.tool(name="warehouse_inventory", title="창고 재고 조회", description="창고 코드 기준으로 재고 현황을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def warehouse_inventory(warehouse_code: str):
    s = _crc(warehouse_code)
    return json.dumps({"warehouse_code": warehouse_code,
        "location": _pick(["김포","인천","부산","대전"],s),
        "total_capacity": 10000, "used": 6000+s%3000,
        "available_slots": 4000-s%3000,
        "last_audit": "2026-04-05 09:00"}, ensure_ascii=False, indent=2)

@mcp.tool(name="carrier_lookup", title="운송사 조회", description="운송사 정보 및 가용 차량을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def carrier_lookup(carrier_name: str):
    s = _crc(carrier_name)
    return json.dumps({"carrier_name": carrier_name,
        "available_vehicles": s%10+1, "vehicle_types": ["1톤","2.5톤","5톤","11톤"],
        "service_area": ["수도권","전국"], "contact": f"02-{s%9000+1000}-{s%9000+1000}"}, ensure_ascii=False, indent=2)

@mcp.tool(name="delivery_schedule", title="배송 일정 조회", description="날짜 기준으로 배송 일정을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def delivery_schedule(date: str, warehouse_code: str = "WH-001"):
    s = _crc(date+warehouse_code)
    return json.dumps({"date": date, "warehouse_code": warehouse_code,
        "scheduled_shipments": s%50+10, "dispatched": s%30,
        "pending": s%50+10-s%30, "urgent": s%5}, ensure_ascii=False, indent=2)

@mcp.tool(name="customs_status_lookup", title="통관 상태 조회", description="수입 화물의 통관 상태를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def customs_status_lookup(tracking_number: str):
    s = _crc(tracking_number+"customs")
    return json.dumps({"tracking_number": tracking_number,
        "customs_status": _pick(["CLEARED","UNDER_INSPECTION","HELD","PENDING"],s),
        "declaration_number": f"DEC-{s%900000+100000}",
        "estimated_clearance": _pick(["완료","1~2영업일","검사 중"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="dispatch_vehicle", title="배차 지시", description="화물에 대해 차량을 배차합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def dispatch_vehicle(tracking_number: str, vehicle_type: str, priority: str = "normal"):
    return json.dumps({"tracking_number": tracking_number, "dispatch_id": _rid("DSP"),
        "vehicle_type": vehicle_type, "priority": priority,
        "status": "DISPATCHED", "dispatched_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="reroute_shipment", title="경로 변경", description="운송 중 화물의 배송지를 변경합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def reroute_shipment(tracking_number: str, new_destination: str, reason: str):
    s = _crc(tracking_number+"reroute")
    return json.dumps({"tracking_number": tracking_number, "new_destination": new_destination,
        "status": "REROUTED", "additional_fee": _pick([0,5000,15000,30000],s),
        "reason": reason, "rerouted_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="file_damage_claim", title="화물 클레임 접수", description="파손/분실에 대한 클레임을 접수합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def file_damage_claim(tracking_number: str, damage_type: str, description: str):
    return json.dumps({"claim_id": _rid("CLM"), "tracking_number": tracking_number,
        "damage_type": damage_type, "description": description,
        "status": "FILED", "filed_at": _now(),
        "estimated_review": "접수 후 3~5영업일"}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_ops_note", title="운영 노트 기록", description="운영 처리 내역을 기록합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_ops_note(entity_id: str, note: str, entity_type: str = "shipment", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("OP"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
