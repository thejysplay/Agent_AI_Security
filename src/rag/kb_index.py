from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple
import json
import numpy as np

import faiss  # faiss-cpu

from rag.embedder import Embedder, EmbedderConfig


@dataclass
class KBIndexConfig:
    docs_dir: Path
    index_dir: Path
    model_name_or_path: str = "sentence-transformers/all-MiniLM-L6-v2"
    chunk_chars: int = 800
    chunk_overlap: int = 150

def _iter_docs(docs_dir: Path) -> List[Path]:
    exts = {".md", ".txt"}
    files = []
    for p in docs_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            files.append(p)
    return sorted(files)

def _chunk_text(text: str, chunk_chars: int, overlap: int) -> List[str]:
    if chunk_chars <= 0:
        return [text]
    chunks = []
    i = 0
    n = len(text)
    while i < n:
        j = min(n, i + chunk_chars)
        chunks.append(text[i:j])
        if j == n:
            break
        i = max(0, j - overlap)
    return chunks

def build_index(cfg: KBIndexConfig) -> Dict[str, int]:
    cfg.index_dir.mkdir(parents=True, exist_ok=True)

    files = _iter_docs(cfg.docs_dir)
    if not files:
        raise RuntimeError(f"No docs found in: {cfg.docs_dir}")

    embedder = Embedder(EmbedderConfig(model_name_or_path=cfg.model_name_or_path, normalize=True))

    texts: List[str] = []
    metas: List[Dict] = []

    for fp in files:
        raw = fp.read_text(encoding="utf-8", errors="ignore")
        chunks = _chunk_text(raw, cfg.chunk_chars, cfg.chunk_overlap)
        for k, ch in enumerate(chunks):
            texts.append(ch)
            metas.append({
                "source_path": str(fp),
                "chunk_id": k,
                "text": ch,
            })

    vecs = embedder.encode(texts)  # (N, D)
    dim = vecs.shape[1]

    # cosine similarity = inner product on normalized vectors
    index = faiss.IndexFlatIP(dim)
    index.add(vecs)

    faiss_path = cfg.index_dir / "index.faiss"
    meta_path = cfg.index_dir / "meta.jsonl"

    faiss.write_index(index, str(faiss_path))
    with meta_path.open("w", encoding="utf-8") as f:
        for m in metas:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")

    return {"num_docs": len(files), "num_chunks": len(metas), "dim": dim}

def load_index(index_dir: Path):
    faiss_path = index_dir / "index.faiss"
    meta_path = index_dir / "meta.jsonl"
    if not faiss_path.exists() or not meta_path.exists():
        raise RuntimeError(f"Index not found. Build first: {index_dir}")

    index = faiss.read_index(str(faiss_path))
    metas = []
    with meta_path.open("r", encoding="utf-8") as f:
        for line in f:
            metas.append(json.loads(line))
    return index, metas

def search(index_dir: Path, query: str, top_k: int, model_name_or_path: str) -> List[Dict]:
    index, metas = load_index(index_dir)
    embedder = Embedder(EmbedderConfig(model_name_or_path=model_name_or_path, normalize=True))

    qv = embedder.encode([query])  # (1, D)
    scores, ids = index.search(qv, top_k)

    out = []
    for rank, (s, idx) in enumerate(zip(scores[0].tolist(), ids[0].tolist()), start=1):
        if idx < 0:
            continue
        m = metas[idx]
        out.append({
            "rank": rank,
            "score": float(s),
            "source_path": m["source_path"],
            "chunk_id": m["chunk_id"],
            "text": m["text"],
        })
    return out
