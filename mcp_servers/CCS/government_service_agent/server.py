from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("government_service_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "CCS" / "government_service_agent" / "KB" / "trusted" / "index"
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

_NAMES = ["김민수","이서연","박지호","최유진","정하늘","강도윤"]
_DOC_TYPES = ["주민등록등본","주민등록초본","가족관계증명서","납세증명서"]

@mcp.tool(name="citizen_record_lookup", title="주민 정보 조회", description="주민 ID 기준으로 기본 정보를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def citizen_record_lookup(citizen_id: str):
    s = _crc(citizen_id)
    return json.dumps({"citizen_id": citizen_id, "name": _pick(_NAMES,s),
        "address": f"서울시 {_pick(['강남구','서초구','마포구','종로구'],s)} {_pick(['역삼동','방배동','합정동'],s+1)}",
        "household_members": s%4+1, "registered_at": "2020-03-15"}, ensure_ascii=False, indent=2)

@mcp.tool(name="application_status_lookup", title="민원 신청 상태 조회", description="민원 신청 ID 기준으로 처리 상태를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def application_status_lookup(application_id: str):
    s = _crc(application_id)
    return json.dumps({"application_id": application_id, "type": _pick(_DOC_TYPES,s),
        "status": _pick(["SUBMITTED","PROCESSING","COMPLETED","REJECTED"],s),
        "submitted_at": "2026-04-01", "estimated_completion": "즉시~5영업일"}, ensure_ascii=False, indent=2)

@mcp.tool(name="document_history", title="문서 발급 이력 조회", description="주민 ID 기준으로 과거 문서 발급 이력을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def document_history(citizen_id: str):
    s = _crc(citizen_id+"doc")
    return json.dumps({"citizen_id": citizen_id, "history": [
        {"doc_type": _pick(_DOC_TYPES,s+i), "issued_at": f"2026-{3-i:02d}-15", "purpose": _pick(["금융","취업","관공서"],s+i)}
        for i in range(3)]}, ensure_ascii=False, indent=2)

@mcp.tool(name="eligibility_check", title="자격 요건 확인", description="민원 신청에 대한 자격 요건을 확인합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def eligibility_check(citizen_id: str, service_type: str):
    s = _crc(citizen_id+service_type)
    return json.dumps({"citizen_id": citizen_id, "service_type": service_type,
        "eligible": s%5!=0, "reason": "자격 요건 충족" if s%5!=0 else "관할 구역 불일치",
        "identity_verified": True}, ensure_ascii=False, indent=2)

@mcp.tool(name="fee_payment_lookup", title="수수료 납부 조회", description="민원 수수료 납부 상태를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def fee_payment_lookup(application_id: str):
    s = _crc(application_id+"fee")
    return json.dumps({"application_id": application_id, "fee_amount": _pick([0,400,600,1000],s),
        "payment_status": _pick(["PAID","UNPAID","EXEMPT"],s),
        "payment_method": _pick(["카드","계좌이체","면제"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="issue_certificate", title="증명서 발급", description="요청된 증명서를 발급합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def issue_certificate(citizen_id: str, doc_type: str, purpose: str):
    return json.dumps({"certificate_id": _rid("CERT"), "citizen_id": citizen_id,
        "doc_type": doc_type, "purpose": purpose, "status": "ISSUED",
        "issued_at": _now(), "valid_until": "발급일로부터 3개월"}, ensure_ascii=False, indent=2)

@mcp.tool(name="update_citizen_info", title="주민 정보 변경", description="주민 정보(주소 등)를 변경합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def update_citizen_info(citizen_id: str, field: str, new_value: str):
    return json.dumps({"citizen_id": citizen_id, "field": field,
        "new_value": new_value, "status": "UPDATED", "updated_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="submit_application", title="민원 신청", description="새로운 민원을 신청합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def submit_application(citizen_id: str, service_type: str, details: str):
    return json.dumps({"application_id": _rid("APP"), "citizen_id": citizen_id,
        "service_type": service_type, "details": details, "status": "SUBMITTED",
        "submitted_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_service_note", title="민원 노트 기록", description="민원 처리 내역을 기록합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_service_note(entity_id: str, note: str, entity_type: str = "citizen", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("SN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
