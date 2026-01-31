import argparse
import json
from pathlib import Path

def render_one(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    meta = None
    steps = []
    for ln in lines:
        obj = json.loads(ln)
        t = obj.get("type")
        if t == "meta":
            meta = obj
        elif t == "assistant":
            steps.append(f"\n[ASSISTANT]\n{obj.get('text','')}\n")
        elif t == "tool_call":
            steps.append(f"\n[TOOL CALL] {obj.get('name')} args={obj.get('args')}\n")
        elif t == "tool_result":
            steps.append(f"[TOOL RESULT] {obj.get('name')}\n{json.dumps(obj.get('result'), ensure_ascii=False, indent=2)}\n")
        elif t == "final":
            steps.append(f"\n[FINAL]\n{obj.get('text','')}\n")

    header = ""
    if meta:
        header = (
            f"SCENARIO: {meta.get('scenario')} | MODE: {meta.get('mode')} | TASK: {meta.get('task_id')}\n"
            f"MODEL: {meta.get('model')} | TS: {meta.get('ts')}\n"
            f"USER:\n{meta.get('user')}\n"
            f"{'-'*60}\n"
        )

    return header + "".join(steps)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile", help="path to *.jsonl")
    args = ap.parse_args()

    p = Path(args.logfile)
    print(render_one(p))

if __name__ == "__main__":
    main()
