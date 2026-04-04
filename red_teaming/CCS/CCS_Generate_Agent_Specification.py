from __future__ import annotations

import argparse
import asyncio
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, Iterable, List, Optional, Tuple

import yaml


DEFAULT_REPO_ROOT = Path("/home/user/[11] YeonSu/2026 자료/Agent AI Security")
DEFAULT_CONFIGS_DIR = DEFAULT_REPO_ROOT / "configs" / "CCS"
DEFAULT_MCP_ROOT = DEFAULT_REPO_ROOT / "mcp_servers" / "CCS"
DEFAULT_OUT_ROOT = DEFAULT_REPO_ROOT / "red_teaming" / "CCS"


def normalize_key(text: str) -> str:
    return str(text).strip().lower().replace("-", "_").replace(" ", "_")


def humanize_identifier(text: str) -> str:
    s = text.strip()
    s = s.replace("_and_", " / ")
    s = s.replace("_", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def extract_role_summary(system_prompt: str) -> str:
    for line in system_prompt.splitlines():
        stripped = line.strip()
        if stripped.startswith("역할:"):
            return stripped.split(":", 1)[1].strip()
        if stripped.lower().startswith("role:"):
            return stripped.split(":", 1)[1].strip()

    for line in system_prompt.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("[") and not stripped.startswith("-"):
            return stripped

    return "역할 설명 없음"


def dump_yaml_preserve_multiline(data: Any) -> str:
    class LiteralDumper(yaml.SafeDumper):
        pass

    def str_representer(dumper: yaml.SafeDumper, value: str):
        if "\n" in value:
            return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", value)

    LiteralDumper.add_representer(str, str_representer)
    return yaml.dump(data, Dumper=LiteralDumper, allow_unicode=True, sort_keys=False)


def read_yaml_file(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML 최상위 구조가 dict가 아닙니다: {path}")
    return data


def iter_leaf_nodes(obj: Any, path: Tuple[str, ...] = ()) -> Iterable[Tuple[Tuple[str, ...], Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from iter_leaf_nodes(v, path + (str(k),))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from iter_leaf_nodes(v, path + (str(i),))
    else:
        yield path, obj


def get_nested_value_flexible(data: Any, keys: Tuple[str, ...]) -> Any:
    cur = data
    for key in keys:
        if not isinstance(cur, dict):
            return None

        target = normalize_key(key)
        matched_key = None
        for real_key in cur.keys():
            if normalize_key(str(real_key)) == target:
                matched_key = real_key
                break

        if matched_key is None:
            return None
        cur = cur[matched_key]
    return cur


def maybe_read_text_file(path_str: str, base_dirs: List[Path]) -> Optional[Tuple[str, Path]]:
    s = str(path_str).strip()
    if not s:
        return None

    raw = Path(s)
    candidates: List[Path] = []

    if raw.is_absolute():
        candidates.append(raw)
    else:
        for base in base_dirs:
            candidates.append((base / raw).resolve())

    # 중복 제거
    seen = set()
    unique_candidates: List[Path] = []
    for p in candidates:
        if str(p) not in seen:
            seen.add(str(p))
            unique_candidates.append(p)

    for candidate in unique_candidates:
        if candidate.exists() and candidate.is_file():
            try:
                return candidate.read_text(encoding="utf-8").strip(), candidate
            except UnicodeDecodeError:
                return candidate.read_text(encoding="utf-8-sig").strip(), candidate

    return None


def looks_like_path(value: str) -> bool:
    s = value.strip()
    if not s or "\n" in s:
        return False
    return any(
        [
            "/" in s,
            "\\" in s,
            s.endswith(".txt"),
            s.endswith(".md"),
            s.endswith(".prompt"),
            s.endswith(".yaml"),
            s.endswith(".yml"),
        ]
    )


def resolve_text_or_inline(
    value: str,
    *,
    config_path: Path,
    repo_root: Path,
) -> Tuple[str, Optional[Path]]:
    base_dirs = [config_path.parent, repo_root]

    file_result = maybe_read_text_file(value, base_dirs)
    if file_result is not None:
        return file_result[0], file_result[1]

    return value.strip(), None


def require_text_file(
    value: str,
    *,
    config_path: Path,
    repo_root: Path,
) -> Tuple[str, Path]:
    base_dirs = [config_path.parent, repo_root]
    file_result = maybe_read_text_file(value, base_dirs)
    if file_result is None:
        raise FileNotFoundError(
            f"프롬프트 파일을 찾을 수 없습니다: {value} "
            f"(config={config_path})"
        )
    return file_result[0], file_result[1]


def extract_system_prompt(config: dict, config_path: Path, repo_root: Path) -> Tuple[str, Optional[Path]]:
    # 1) 우선순위가 높은 명시적 경로/필드
    explicit_text_paths = [
        ("system_prompt",),
        ("agent", "system_prompt"),
        ("prompt", "system"),
        ("prompts", "system"),
        ("agent", "prompt", "system"),
        ("system",),
    ]
    explicit_file_paths = [
        ("system_prompt_path",),
        ("agent", "system_prompt_path"),
        ("prompt_path",),
        ("system_path",),
        ("system_file",),
        ("prompt_file",),
        ("agent", "prompt_path"),
        ("agent", "system_path"),
    ]

    for key_path in explicit_text_paths:
        value = get_nested_value_flexible(config, key_path)
        if isinstance(value, str) and value.strip():
            return resolve_text_or_inline(value, config_path=config_path, repo_root=repo_root)

    for key_path in explicit_file_paths:
        value = get_nested_value_flexible(config, key_path)
        if isinstance(value, str) and value.strip():
            return require_text_file(value, config_path=config_path, repo_root=repo_root)

    # 2) 리프 노드 전체 탐색 fallback
    leaf_nodes = list(iter_leaf_nodes(config))

    for path, value in leaf_nodes:
        if not isinstance(value, str) or not value.strip():
            continue

        joined = ".".join(normalize_key(p) for p in path)
        last = normalize_key(path[-1]) if path else ""

        if any(
            [
                "system_prompt" in joined,
                "system_message" in joined,
                joined.endswith(".system"),
                last == "system",
            ]
        ):
            return resolve_text_or_inline(value, config_path=config_path, repo_root=repo_root)

    for path, value in leaf_nodes:
        if not isinstance(value, str) or not value.strip():
            continue

        joined = ".".join(normalize_key(p) for p in path)
        last = normalize_key(path[-1]) if path else ""

        if any(
            [
                "system_prompt_path" in joined,
                "prompt_path" in joined,
                "system_path" in joined,
                last in {"system_file", "prompt_file"},
            ]
        ):
            return require_text_file(value, config_path=config_path, repo_root=repo_root)

    # 3) 마지막 fallback: multiline prompt처럼 보이는 문자열 탐색
    for _, value in leaf_nodes:
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text:
            continue
        if "\n" in text and any(
            marker in text for marker in ["역할:", "Role:", "[TRACE RULE]", "[정책", "당신은", "You are"]
        ):
            return text, None

    raise ValueError(f"system prompt를 config에서 추출하지 못했습니다: {config_path}")


def extract_display_name(config: dict, agent_name: str) -> str:
    candidates = [
        ("display_name",),
        ("agent", "display_name"),
        ("name",),
        ("agent", "name"),
        ("title",),
        ("agent", "title"),
    ]

    for key_path in candidates:
        value = get_nested_value_flexible(config, key_path)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return humanize_identifier(agent_name)


def extract_summary(config: dict, system_prompt: str) -> str:
    candidates = [
        ("summary",),
        ("agent", "summary"),
        ("description",),
        ("agent", "description"),
        ("agent_summary",),
    ]

    for key_path in candidates:
        value = get_nested_value_flexible(config, key_path)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return extract_role_summary(system_prompt)


def tool_to_dict(tool: Any) -> dict:
    if hasattr(tool, "model_dump"):
        data = tool.model_dump(exclude_none=True)
    elif hasattr(tool, "dict"):
        data = tool.dict(exclude_none=True)
    else:
        data = {
            k: v
            for k, v in vars(tool).items()
            if not k.startswith("_") and v is not None
        }

    if "inputSchema" in data and "input_schema" not in data:
        data["input_schema"] = data.pop("inputSchema")

    return data


async def fetch_tools_via_mcp(server_path: Path, python_executable: str) -> List[dict]:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except Exception as exc:
        raise RuntimeError(
            "mcp 패키지를 불러오지 못했습니다. 사용자 환경에서 `mcp`가 설치되어 있어야 합니다."
        ) from exc

    params = StdioServerParameters(
        command=python_executable,
        args=[str(server_path)],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            raw_tools = getattr(result, "tools", []) or []

    return [tool_to_dict(tool) for tool in raw_tools]


def find_ccs_config_files(configs_dir: Path, agent_name: Optional[str] = None) -> List[Path]:
    if not configs_dir.exists():
        raise FileNotFoundError(f"CCS config 폴더를 찾을 수 없습니다: {configs_dir}")

    files = sorted(list(configs_dir.glob("*.yml")) + list(configs_dir.glob("*.yaml")))
    if agent_name:
        files = [p for p in files if p.stem == agent_name]

    if not files:
        if agent_name:
            raise FileNotFoundError(f"해당 agent의 config를 찾을 수 없습니다: {agent_name}")
        raise FileNotFoundError(f"config 파일이 없습니다: {configs_dir}")

    return files


def build_server_path(mcp_root: Path, agent_name: str) -> Path:
    server_path = mcp_root / agent_name / "server.py"
    if not server_path.exists():
        raise FileNotFoundError(f"server.py를 찾을 수 없습니다: {server_path}")
    return server_path


async def generate_one_agent_profile_from_config(
    *,
    config_path: Path,
    repo_root: Path,
    mcp_root: Path,
    out_root: Path,
    python_executable: str,
) -> Path:
    agent_name = config_path.stem
    config = read_yaml_file(config_path)
    server_path = build_server_path(mcp_root, agent_name)

    system_prompt, prompt_source_path = extract_system_prompt(
        config=config,
        config_path=config_path,
        repo_root=repo_root,
    )
    display_name = extract_display_name(config, agent_name)
    summary = extract_summary(config, system_prompt)
    tools = await fetch_tools_via_mcp(server_path=server_path, python_executable=python_executable)

    today = date.today().isoformat()
    save_dir = out_root / "agent_profiles" / agent_name / today
    save_dir.mkdir(parents=True, exist_ok=True)
    save_path = save_dir / "agent_profile.yaml"

    payload = {
        "header": "Agent profile",
        "agent": {
            "id": agent_name,
            "display_name": display_name,
            "summary": summary,
        },
        "system_prompt": system_prompt,
        "tools": tools
    }

    save_path.write_text(dump_yaml_preserve_multiline(payload), encoding="utf-8")
    return save_path


async def generate_profiles_batch(
    *,
    repo_root: Path,
    configs_dir: Path,
    mcp_root: Path,
    out_root: Path,
    python_executable: str,
    agent_name: Optional[str] = None,
) -> int:
    config_files = find_ccs_config_files(configs_dir, agent_name=agent_name)

    ok_count = 0
    fail_count = 0

    print(f"[INFO] repo_root   = {repo_root}")
    print(f"[INFO] configs_dir = {configs_dir}")
    print(f"[INFO] mcp_root    = {mcp_root}")
    print(f"[INFO] out_root    = {out_root}")
    print(f"[INFO] targets     = {len(config_files)}")

    for config_path in config_files:
        agent = config_path.stem
        try:
            save_path = await generate_one_agent_profile_from_config(
                config_path=config_path,
                repo_root=repo_root,
                mcp_root=mcp_root,
                out_root=out_root,
                python_executable=python_executable,
            )
        except Exception as exc:
            fail_count += 1
            print(f"[ERROR] agent={agent} :: {exc}", file=sys.stderr)
            continue

        ok_count += 1
        print(f"[OK] agent={agent} saved: {save_path}")

    print()
    print("[SUMMARY]")
    print(f"  success = {ok_count}")
    print(f"  failed  = {fail_count}")
    print(f"  total   = {len(config_files)}")

    return 0 if fail_count == 0 else 1


async def _amain() -> int:
    parser = argparse.ArgumentParser(
        description="Generate CCS agent profiles from configs/CCS + mcp_servers/CCS"
    )
    parser.add_argument(
        "--repo-root",
        default=str(DEFAULT_REPO_ROOT),
        help="프로젝트 루트 경로",
    )
    parser.add_argument(
        "--configs-dir",
        default=str(DEFAULT_CONFIGS_DIR),
        help="CCS config 폴더 경로",
    )
    parser.add_argument(
        "--mcp-root",
        default=str(DEFAULT_MCP_ROOT),
        help="CCS MCP server 루트 경로",
    )
    parser.add_argument(
        "--out-root",
        default=str(DEFAULT_OUT_ROOT),
        help="출력 루트 경로",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="MCP server.py 실행에 사용할 Python 실행 파일 경로",
    )
    parser.add_argument(
        "--agent",
        default=None,
        help="특정 agent 하나만 생성할 때 사용. 예: banking_cs_agent",
    )

    args = parser.parse_args()

    repo_root = Path(args.repo_root)
    configs_dir = Path(args.configs_dir)
    mcp_root = Path(args.mcp_root)
    out_root = Path(args.out_root)

    return await generate_profiles_batch(
        repo_root=repo_root,
        configs_dir=configs_dir,
        mcp_root=mcp_root,
        out_root=out_root,
        python_executable=args.python,
        agent_name=args.agent,
    )


def main() -> None:
    raise SystemExit(asyncio.run(_amain()))


if __name__ == "__main__":
    main()