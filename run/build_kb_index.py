from __future__ import annotations

import shutil
import sys
from pathlib import Path

# ----------------------------
# Path setup (no PYTHONPATH needed)
# ----------------------------
ROOT = Path(__file__).resolve().parents[1]  # repo root
SRC_DIR = ROOT / "src"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SRC_DIR))

# Try both import styles (repo layout에 따라 다름)
try:
    # src-layout (recommended)
    from rag.kb_index import KBIndexConfig, build_index  # type: ignore
except Exception:
    # legacy import path (your previous style)
    from src.rag.kb_index import KBIndexConfig, build_index  # type: ignore

# ----------------------------
# Config
# ----------------------------
SCENARIO_DIR = ROOT / "scenarios" / "system_admin_agent" / "KB"
EMB_MODEL = "intfloat/multilingual-e5-small"  # 로컬 경로로 바꿔도 됨

CHUNK_CHARS = 800
CHUNK_OVERLAP = 150

# 매번 기존 인덱스 삭제 후 새로 생성 (원하면 False로)
CLEAR_INDEX_DIR_BEFORE_BUILD = True


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
    """
    build_index()가 어떤 파일명으로 저장하든,
    서버가 기대하는 파일명으로 통일:
      - faiss.index (필수)
      - meta.jsonl (필수)
    """
    faiss_expected = index_dir / "faiss.index"
    legacy_a = index_dir / "index.faiss"
    legacy_b = index_dir / "index.faiss.index"  # 혹시 이상하게 만들어진 케이스 방지

    # 1) faiss.index가 없으면, index.faiss를 rename
    if not faiss_expected.exists():
        if legacy_a.exists():
            legacy_a.rename(faiss_expected)
        elif legacy_b.exists():
            legacy_b.rename(faiss_expected)

    # 2) 그래도 없으면 실패
    if not faiss_expected.exists():
        raise FileNotFoundError(
            f"[RAG] faiss.index not found after build. index_dir={index_dir}"
        )

    # meta.jsonl 체크
    meta = index_dir / "meta.jsonl"
    if not meta.exists():
        raise FileNotFoundError(
            f"[RAG] meta.jsonl not found after build. index_dir={index_dir}"
        )


def build_one(name: str, docs_dir: Path, index_dir: Path):
    print(f"[Build] {name}")
    print(f"  docs_dir : {docs_dir}")
    print(f"  index_dir: {index_dir}")

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

    # ✅ 가장 중요: 파일명 정규화
    normalize_faiss_filename(index_dir)

    print(f"  [OK] wrote: {index_dir / 'faiss.index'}")
    print(f"  [OK] wrote: {index_dir / 'meta.jsonl'}\n")


def main():
    # TRUSTED
    trusted_docs = SCENARIO_DIR / "trusted" / "docs"
    trusted_index = SCENARIO_DIR / "trusted" / "index"

    # UNTRUSTED
    untrusted_docs = SCENARIO_DIR / "untrusted" / "docs"
    untrusted_index = SCENARIO_DIR / "untrusted" / "index"

    build_one("trusted KB", trusted_docs, trusted_index)
    build_one("untrusted KB", untrusted_docs, untrusted_index)

    print("[OK] KB indexing done (faiss.index normalized)")


if __name__ == "__main__":
    main()
