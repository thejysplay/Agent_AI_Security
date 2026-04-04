from __future__ import annotations

import shutil
import sys
from pathlib import Path

# ----------------------------
# Path setup
# ----------------------------
ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SRC_DIR))

try:
    from rag.kb_index import KBIndexConfig, build_index
except Exception:
    from src.rag.kb_index import KBIndexConfig, build_index

# ----------------------------
# Config
# ----------------------------
CCS_SCENARIOS_DIR = ROOT / "scenarios" / "CCS"
EMB_MODEL = "intfloat/multilingual-e5-small"

CHUNK_CHARS = 800
CHUNK_OVERLAP = 150
CLEAR_INDEX_DIR_BEFORE_BUILD = True

AGENTS = [
    "ecommerce_operations_agent",
    "travel_reservation_agent",
    "banking_cs_agent",
    "insurance_claims_agent",
    "medical_consultation_agent",
    "hr_onboarding_agent",
    "education_admin_agent",
    "government_service_agent",
    "telecom_cs_agent",
    "logistics_operations_agent",
]


def clear_dir(dir_path: Path):
    if not dir_path.exists():
        dir_path.mkdir(parents=True, exist_ok=True)
        return
    for p in dir_path.iterdir():
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()


def normalize_faiss_filename(index_dir: Path):
    faiss_expected = index_dir / "faiss.index"
    legacy_a = index_dir / "index.faiss"
    legacy_b = index_dir / "index.faiss.index"

    if not faiss_expected.exists():
        if legacy_a.exists():
            legacy_a.rename(faiss_expected)
        elif legacy_b.exists():
            legacy_b.rename(faiss_expected)

    if not faiss_expected.exists():
        raise FileNotFoundError(
            f"[RAG] faiss.index not found after build. index_dir={index_dir}"
        )

    meta = index_dir / "meta.jsonl"
    if not meta.exists():
        raise FileNotFoundError(
            f"[RAG] meta.jsonl not found after build. index_dir={index_dir}"
        )


def build_one(name: str, docs_dir: Path, index_dir: Path):
    print(f"[Build] {name}")
    print(f"  docs_dir : {docs_dir}")
    print(f"  index_dir: {index_dir}")

    if not docs_dir.exists():
        print(f"  [SKIP] docs_dir not found: {docs_dir}\n")
        return

    doc_files = list(docs_dir.glob("*.md"))
    if not doc_files:
        print(f"  [SKIP] no .md files in {docs_dir}\n")
        return

    print(f"  found {len(doc_files)} doc(s)")

    index_dir.mkdir(parents=True, exist_ok=True)
    if CLEAR_INDEX_DIR_BEFORE_BUILD:
        clear_dir(index_dir)

    result = build_index(
        KBIndexConfig(
            docs_dir=docs_dir,
            index_dir=index_dir,
            model_name_or_path=EMB_MODEL,
            chunk_chars=CHUNK_CHARS,
            chunk_overlap=CHUNK_OVERLAP,
        )
    )
    print("  result:", result)

    normalize_faiss_filename(index_dir)

    print(f"  [OK] wrote: {index_dir / 'faiss.index'}")
    print(f"  [OK] wrote: {index_dir / 'meta.jsonl'}\n")


def main():
    if not CCS_SCENARIOS_DIR.exists():
        print(f"[ERROR] CCS scenarios dir not found: {CCS_SCENARIOS_DIR}")
        sys.exit(1)

    success = 0
    fail = 0

    for agent in AGENTS:
        kb_dir = CCS_SCENARIOS_DIR / agent / "KB"
        trusted_docs = kb_dir / "trusted" / "docs"
        trusted_index = kb_dir / "trusted" / "index"

        try:
            build_one(f"{agent} (trusted)", trusted_docs, trusted_index)
            success += 1
        except Exception as e:
            print(f"  [ERROR] {agent}: {e}\n")
            fail += 1

    print("=" * 50)
    print(f"[DONE] success={success}, fail={fail}, total={len(AGENTS)}")


if __name__ == "__main__":
    main()