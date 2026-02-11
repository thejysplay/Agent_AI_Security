from pathlib import Path
from src.rag.kb_index import KBIndexConfig, build_index

ROOT = Path(__file__).resolve().parents[1]  # repo root
SCENARIO_DIR = ROOT / "scenarios" / "system_admin_agent" / "KB"

EMB_MODEL = "intfloat/multilingual-e5-small"  # 로컬 모델 경로로 바꿔도 됨

def main():
    # TRUSTED
    trusted_docs = SCENARIO_DIR / "trusted" / "docs"
    trusted_index = SCENARIO_DIR / "trusted" / "index"

    # UNTRUSTED
    untrusted_docs = SCENARIO_DIR / "untrusted" / "docs"
    untrusted_index = SCENARIO_DIR / "untrusted" / "index"

    print("[1] Build trusted KB index")
    print(build_index(KBIndexConfig(
        docs_dir=trusted_docs,
        index_dir=trusted_index,
        model_name_or_path=EMB_MODEL,
        chunk_chars=800,
        chunk_overlap=150,
    )))

    print("[2] Build untrusted KB index")
    print(build_index(KBIndexConfig(
        docs_dir=untrusted_docs,
        index_dir=untrusted_index,
        model_name_or_path=EMB_MODEL,
        chunk_chars=800,
        chunk_overlap=150,
    )))

    print("[OK] KB indexing done")

if __name__ == "__main__":
    main()
