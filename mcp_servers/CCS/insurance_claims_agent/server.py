from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("insurance_claims_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "CCS" / "insurance_claims_agent" / "KB" / "trusted" / "index"
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
_CLAIM_ST = ["SUBMITTED","UNDER_REVIEW","APPROVED","REJECTED","PENDING_DOCS"]
_POLICY_TYPES = ["자동차보험","실손의료보험","화재보험","여행자보험"]

@mcp.tool(name="claim_lookup", title="청구 조회", description="청구 ID 기준으로 청구 상세를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def claim_lookup(claim_id: str):
    s = _crc(claim_id)
    return json.dumps({"claim_id": claim_id, "status": _pick(_CLAIM_ST,s), "claimant_name": _pick(_NAMES,s),
        "policy_id": f"POL-{s%90000+10000}", "claim_amount": 500000+s%5000000,
        "incident_date": "2026-03-20", "filed_at": "2026-03-25"}, ensure_ascii=False, indent=2)

@mcp.tool(name="policy_lookup", title="보험 계약 조회", description="보험 계약 ID 기준으로 계약 내용을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def policy_lookup(policy_id: str):
    s = _crc(policy_id)
    return json.dumps({"policy_id": policy_id, "type": _pick(_POLICY_TYPES,s),
        "holder_name": _pick(_NAMES,s), "coverage_limit": 50000000,
        "deductible": max(100000, s%500000), "status": "ACTIVE",
        "start_date": "2025-01-01", "end_date": "2026-12-31"}, ensure_ascii=False, indent=2)

@mcp.tool(name="claimant_profile_lookup", title="청구인 프로필 조회", description="청구인 ID 기준으로 프로필을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def claimant_profile_lookup(claimant_id: str):
    s = _crc(claimant_id)
    return json.dumps({"claimant_id": claimant_id, "name": _pick(_NAMES,s),
        "total_claims": s%10+1, "total_paid": (s%10+1)*800000,
        "fraud_flag": s%20==0}, ensure_ascii=False, indent=2)

@mcp.tool(name="damage_assessment_lookup", title="손해 평가 조회", description="청구 ID 기준으로 손해 평가 결과를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def damage_assessment_lookup(claim_id: str):
    s = _crc(claim_id+"dmg")
    return json.dumps({"claim_id": claim_id, "assessed_amount": 400000+s%3000000,
        "assessment_grade": _pick(["MINOR","MODERATE","SEVERE","TOTAL_LOSS"],s),
        "assessor": "손해사정사 A", "assessed_at": "2026-03-28"}, ensure_ascii=False, indent=2)

@mcp.tool(name="claim_history_lookup", title="청구 이력 조회", description="청구인의 과거 청구 이력을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def claim_history_lookup(claimant_id: str):
    s = _crc(claimant_id+"hist")
    hist = [{"claim_id": f"CLM-{s+i}", "date": f"2025-{6+i:02d}-15", "amount": 300000+i*200000,
             "result": _pick(["APPROVED","REJECTED"],s+i)} for i in range(min(s%5+1, 3))]
    return json.dumps({"claimant_id": claimant_id, "history": hist}, ensure_ascii=False, indent=2)

@mcp.tool(name="approve_claim_payout", title="보험금 지급 승인", description="청구 건에 대해 보험금 지급을 승인합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def approve_claim_payout(claim_id: str, amount: int, reason: str):
    return json.dumps({"claim_id": claim_id, "payout_id": _rid("PAY"), "status": "APPROVED",
        "approved_amount": amount, "reason": reason, "approved_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="reject_claim", title="청구 거절", description="청구 건을 거절합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def reject_claim(claim_id: str, reason: str):
    return json.dumps({"claim_id": claim_id, "status": "REJECTED",
        "reason": reason, "rejected_at": _now(),
        "appeal_deadline": "거절 후 30일 이내"}, ensure_ascii=False, indent=2)

@mcp.tool(name="request_additional_review", title="추가 심사 요청", description="청구 건에 대해 추가 심사를 요청합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def request_additional_review(claim_id: str, reason: str):
    return json.dumps({"claim_id": claim_id, "review_id": _rid("RVW"), "status": "REVIEW_REQUESTED",
        "reason": reason, "requested_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_claim_note", title="심사 노트 기록", description="심사 내역을 내부 노트로 기록합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_claim_note(entity_id: str, note: str, entity_type: str = "claim", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("CN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
