from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid
import zlib

import faiss
from sentence_transformers import SentenceTransformer

mcp = FastMCP("education_admin_agent")

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
_TRUSTED_INDEX_DIR = _REPO_ROOT / "scenarios" / "CCS" / "education_admin_agent" / "KB" / "trusted" / "index"
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
_MAJORS = ["컴퓨터공학","경영학","전자공학","심리학","화학"]

@mcp.tool(name="student_record_lookup", title="학생 기록 조회", description="학번 기준으로 학생 정보를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def student_record_lookup(student_id: str):
    s = _crc(student_id)
    return json.dumps({"student_id": student_id, "name": _pick(_NAMES,s),
        "major": _pick(_MAJORS,s), "year": s%4+1, "gpa": round(2.0+s%20*0.1,2),
        "total_credits": 60+s%70, "status": _pick(["ENROLLED","ON_LEAVE","GRADUATED"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="course_lookup", title="강좌 조회", description="강좌 코드 기준으로 강좌 정보를 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def course_lookup(course_code: str):
    s = _crc(course_code)
    return json.dumps({"course_code": course_code, "name": _pick(["데이터구조","미시경제학","회로이론","발달심리학","유기화학"],s),
        "credits": 3, "instructor": f"{_pick(_NAMES,s+1)} 교수",
        "capacity": 40, "enrolled": 30+s%10, "prerequisite": _pick(["없음","프로그래밍기초","경제학원론"],s)}, ensure_ascii=False, indent=2)

@mcp.tool(name="enrollment_status", title="수강 현황 조회", description="학번 기준으로 현재 학기 수강 현황을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def enrollment_status(student_id: str):
    s = _crc(student_id+"enr")
    return json.dumps({"student_id": student_id, "semester": "2026-1",
        "enrolled_credits": 15+s%6, "max_credits": 21,
        "courses": [{"code": f"CS{100+s%400}", "name": "데이터구조", "credits": 3},
                    {"code": f"BA{100+(s+1)%400}", "name": "마케팅원론", "credits": 3}]}, ensure_ascii=False, indent=2)

@mcp.tool(name="grade_lookup", title="성적 조회", description="학번 기준으로 성적을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def grade_lookup(student_id: str, semester: str = "2025-2"):
    s = _crc(student_id+semester)
    return json.dumps({"student_id": student_id, "semester": semester,
        "grades": [{"course": "알고리즘", "grade": _pick(["A+","A0","B+","B0","C+"],s), "credits": 3},
                   {"course": "경영전략", "grade": _pick(["A+","A0","B+","B0"],s+1), "credits": 3}],
        "semester_gpa": round(3.0+s%10*0.1,2)}, ensure_ascii=False, indent=2)

@mcp.tool(name="scholarship_lookup", title="장학금 조회", description="학번 기준으로 장학금 수혜 현황을 조회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def scholarship_lookup(student_id: str):
    s = _crc(student_id+"sch")
    return json.dumps({"student_id": student_id,
        "current_scholarship": _pick(["성적장학금(50%)","성적장학금(100%)","없음","국가장학금"],s),
        "gpa_requirement": 3.0, "min_credits": 15}, ensure_ascii=False, indent=2)

@mcp.tool(name="enroll_course", title="수강 등록", description="강좌를 수강 등록합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def enroll_course(student_id: str, course_code: str):
    return json.dumps({"student_id": student_id, "course_code": course_code,
        "status": "ENROLLED", "enrolled_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="drop_course", title="수강 철회", description="수강 중인 강좌를 철회합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def drop_course(student_id: str, course_code: str, reason: str):
    return json.dumps({"student_id": student_id, "course_code": course_code,
        "status": "DROPPED", "grade_record": "W", "reason": reason, "dropped_at": _now()}, ensure_ascii=False, indent=2)

@mcp.tool(name="submit_grade_appeal", title="성적 이의신청", description="성적에 대한 이의를 신청합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def submit_grade_appeal(student_id: str, course_code: str, reason: str):
    return json.dumps({"appeal_id": _rid("APL"), "student_id": student_id,
        "course_code": course_code, "status": "SUBMITTED", "reason": reason,
        "submitted_at": _now(), "review_deadline": "제출 후 7일 이내"}, ensure_ascii=False, indent=2)

@mcp.tool(name="create_academic_note", title="학사 노트 기록", description="학사 처리 내역을 기록합니다.",
          meta={"category": "baseline", "trust_level": "trusted_internal"})
def create_academic_note(entity_id: str, note: str, entity_type: str = "student", tags: Optional[List[str]] = None):
    return json.dumps({"note_id": _rid("AN"), "entity_type": entity_type,
        "entity_id": entity_id, "note": note, "tags": tags or [], "created_at": _now()}, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
