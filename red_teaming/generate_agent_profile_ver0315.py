from __future__ import annotations

import argparse
import asyncio
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, List, Optional

import yaml


DEFAULT_REPO_ROOT = Path("/home/user/[11] YeonSu/2026 자료/Agent AI Security")


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


def validate_paths(repo_root: Path, agent_name: str) -> tuple[Path, Path]:
    system_prompt_path = repo_root / "scenarios" / agent_name / "system.txt"
    server_path = repo_root / "mcp_servers" / agent_name / "normal" / "server.py"

    if not system_prompt_path.exists():
        raise FileNotFoundError(f"system.txt를 찾을 수 없습니다: {system_prompt_path}")
    if not server_path.exists():
        raise FileNotFoundError(f"server.py를 찾을 수 없습니다: {server_path}")

    return system_prompt_path, server_path


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

    params = StdioServerParameters(command=python_executable, args=[str(server_path)])

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            raw_tools = getattr(result, "tools", []) or []

    return [tool_to_dict(tool) for tool in raw_tools]


async def generate_agent_profile(
    agent_name: str,
    repo_root: Path,
    out_root: Optional[Path],
    python_executable: str,
) -> Path:
    system_prompt_path, server_path = validate_paths(repo_root, agent_name)

    system_prompt = system_prompt_path.read_text(encoding="utf-8").strip()
    summary = extract_role_summary(system_prompt)
    tools = await fetch_tools_via_mcp(server_path=server_path, python_executable=python_executable)

    today = date.today().isoformat()
    profile_root = out_root or (repo_root / "red_teaming" / "agent_profiles")
    save_dir = profile_root / agent_name / today
    save_dir.mkdir(parents=True, exist_ok=True)
    save_path = save_dir / "agent_profile.yaml"

    payload = {
        "header": "Agent profile",
        "agent": {
            "id": agent_name,
            "display_name": humanize_identifier(agent_name),
            "summary": summary,
        },
        "system_prompt": system_prompt,
        "tools": tools,
    }

    save_path.write_text(dump_yaml_preserve_multiline(payload), encoding="utf-8")
    return save_path


async def _amain() -> int:
    parser = argparse.ArgumentParser(description="Generate agent profile YAML from system prompt + MCP tools.")
    parser.add_argument("agent_name", help="예: ChatGPT_Agent_Mode")
    parser.add_argument(
        "--repo-root",
        default=str(DEFAULT_REPO_ROOT),
        help="프로젝트 루트 경로",
    )
    parser.add_argument(
        "--out-root",
        default=None,
        help="저장 루트 경로. 기본값은 <repo_root>/red_teaming/agent_profiles",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="MCP server.py 실행에 사용할 Python 실행 파일 경로",
    )

    args = parser.parse_args()
    repo_root = Path(args.repo_root)
    out_root = Path(args.out_root) if args.out_root else None

    try:
        save_path = await generate_agent_profile(
            agent_name=args.agent_name,
            repo_root=repo_root,
            out_root=out_root,
            python_executable=args.python,
        )
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"[OK] saved: {save_path}")
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(_amain()))


if __name__ == "__main__":
    main()