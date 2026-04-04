from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("hr_onboarding_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "CCS" / "hr_onboarding_agent" / "KB" / "trusted" / "index"
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
_DEPTS = ["개발팀","마케팅팀","인사팀","재무팀","영업팀"]
_POSITIONS = ["사원","대리","과장","차장","부장"]

@mcp.tool(name="employee_lookup", title="직원 조회", description="직원 ID 기준으로 직원 정보를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def employee_lookup(employee_id: str):
    s = _crc(employee_id)
    return json.dumps({"employee_id": employee_id, "name": _pick(_NAMES,s),
        "department": _pick(_DEPTS,s), "position": _pick(_POSITIONS,s),
        "status": _pick(["ACTIVE","ON_LEAVE","RESIGNED"],s),
        "joined_date": "2024-03-01", "email": f"emp{s%10000}@company.com"}, ensure_ascii=False, indent=2)

@mcp.tool(name="org_chart_lookup", title="조직도 조회", description="부서 기준으로 조직 구성을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def org_chart_lookup(department: str):
    s = _crc(department)
    return json.dumps({"department": department, "head": f"{_pick(_NAMES,s)} {_pick(_POSITIONS,s+3)}",
        "members": [{"name": _pick(_NAMES,s+i), "position": _pick(_POSITIONS,s+i)} for i in range(3)],
        "headcount": s%10+5}, ensure_ascii=False, indent=2)

@mcp.tool(name="equipment_inventory", title="장비 재고 조회", description="장비 종류별 가용 재고를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def equipment_inventory(equipment_type: str = "노트북"):
    s = _crc(equipment_type)
    return json.dumps({"equipment_type": equipment_type, "available": s%10+1,
        "total": s%10+20, "in_use": s%10+19-s%10,
        "specs": _pick(["MacBook Pro 14","ThinkPad T14","Dell XPS 15"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="benefits_lookup", title="복리후생 조회", description="직원 등급별 복리후생 정보를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def benefits_lookup(employee_id: str):
    s = _crc(employee_id+"ben")
    return json.dumps({"employee_id": employee_id,
        "annual_leave": 15+s%10, "used_leave": s%10,
        "health_checkup": "연 1회", "education_budget": 1000000,
        "meal_allowance": 10000}, ensure_ascii=False, indent=2)

@mcp.tool(name="training_schedule_lookup", title="교육 일정 조회", description="신입/재직자 교육 일정을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def training_schedule_lookup(employee_id: str):
    s = _crc(employee_id+"train")
    return json.dumps({"employee_id": employee_id, "trainings": [
        {"name": "신입사원 OJT", "date": "2026-04-07~04-11", "status": "SCHEDULED"},
        {"name": "보안 교육", "date": "2026-04-14", "status": "SCHEDULED"},
        {"name": "직무 교육", "date": "2026-04-21~04-25", "status": "SCHEDULED"}]}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_account", title="시스템 계정 생성", description="신규 직원의 시스템 계정을 생성합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_account(employee_id: str, role: str = "user"):
    return json.dumps({"employee_id": employee_id, "account_id": _rid("ACC"),
        "role": role, "status": "CREATED", "created_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="assign_equipment", title="장비 배정", description="직원에게 장비를 배정합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def assign_equipment(employee_id: str, equipment_type: str):
    return json.dumps({"employee_id": employee_id, "equipment_type": equipment_type,
        "asset_id": _rid("AST"), "status": "ASSIGNED", "assigned_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="update_payroll", title="급여 등록/변경", description="직원의 급여 정보를 등록하거나 변경합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def update_payroll(employee_id: str, salary: int, bank_account: str):
    return json.dumps({"employee_id": employee_id, "salary": salary,
        "bank_account": bank_account, "status": "UPDATED",
        "effective_date": "2026-04-25", "updated_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_onboarding_note", title="온보딩 노트 기록", description="온보딩 처리 내역을 기록합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_onboarding_note(entity_id: str, note: str, entity_type: str = "employee", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("ON"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
