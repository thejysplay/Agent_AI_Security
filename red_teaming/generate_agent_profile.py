# red_teaming/generate_agent_profile.py
from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# MCP Python SDK
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# ---------------------------
# Utilities
# ---------------------------
def _read_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _abs_args(repo_root: Path, args: List[str]) -> List[str]:
    """
    tools.json에 상대경로("mcp_servers/.../server.py")가 들어오므로,
    repo_root 기준 절대경로로 변환.
    """
    out: List[str] = []
    for a in args:
        p = Path(a)
        out.append(str(p if p.is_absolute() else (repo_root / p)))
    return out


def _tool_to_dict_neutral(tool_obj: Any) -> Dict[str, Any]:
    """
    MCP list_tools()로 받은 tool object를 '중립' 포맷으로 변환.
    - meta / annotations / outputSchema 등은 기록하지 않음
    - sensitive/high_risk 같은 라벨링도 하지 않음
    """
    name = getattr(tool_obj, "name", None)
    title = getattr(tool_obj, "title", None)
    desc = getattr(tool_obj, "description", None)

    # MCP SDK 버전별로 input schema 필드명이 조금 다를 수 있어서 방어적으로 처리
    input_schema = None
    if hasattr(tool_obj, "inputSchema"):
        input_schema = getattr(tool_obj, "inputSchema")
    elif hasattr(tool_obj, "input_schema"):
        input_schema = getattr(tool_obj, "input_schema")

    # pydantic model이면 dict로
    if hasattr(input_schema, "model_dump"):
        input_schema = input_schema.model_dump()
    elif hasattr(input_schema, "dict"):
        input_schema = input_schema.dict()

    d: Dict[str, Any] = {
        "name": name,
        "title": title,
        "description": desc,
        "input_schema": input_schema,
    }

    # None 정리
    return {k: v for k, v in d.items() if v is not None}


async def _list_tools_from_mcp(command: str, args: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    MCP 서버를 stdio로 실행 후 list_tools() 결과를 dict(name -> tool_spec)로 반환
    """
    server_params = StdioServerParameters(command=command, args=args, env=None)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            resp = await session.list_tools()

            tools = getattr(resp, "tools", None) or []
            out: Dict[str, Dict[str, Any]] = {}
            for t in tools:
                td = _tool_to_dict_neutral(t)
                if "name" in td and td["name"]:
                    out[td["name"]] = td
            return out


# ---------------------------
# Core build logic
# ---------------------------
@dataclass
class SourcePaths:
    config: Path
    system_prompt: Path
    normal_tools_json: Path
    attack_tools_json: Path


def _resolve_paths(repo_root: Path, agent_name: str) -> SourcePaths:
    cfg = repo_root / "configs" / f"{agent_name}.yml"
    sys_prompt = repo_root / "scenarios" / agent_name / "system.txt"
    normal_tools = repo_root / "scenarios" / agent_name / "normal_tools.json"
    attack_tools = repo_root / "scenarios" / agent_name / "attack_tools.json"

    missing = [p for p in [cfg, sys_prompt, normal_tools, attack_tools] if not p.exists()]
    if missing:
        raise FileNotFoundError("필수 파일이 없습니다:\n" + "\n".join([str(p) for p in missing]))

    return SourcePaths(cfg, sys_prompt, normal_tools, attack_tools)


def _infer_agent_description(system_prompt_text: str, fallback: str) -> str:
    """
    system.txt의 첫 문장/첫 줄 기반으로 description을 대충 채움.
    (원하면 더 정교하게 파싱 가능)
    """
    for line in system_prompt_text.splitlines():
        s = line.strip()
        if s:
            return s
    return fallback


async def build_agent_profile(repo_root: Path, agent_name: str) -> Tuple[Dict[str, Any], Path]:
    paths = _resolve_paths(repo_root, agent_name)

    cfg = _read_yaml(paths.config)
    system_prompt_text = _read_text(paths.system_prompt)

    normal_tools = _read_json(paths.normal_tools_json)
    attack_tools = _read_json(paths.attack_tools_json)

    baseline_tools: List[str] = cfg.get("baseline_tools") or []
    normal_allowed: List[str] = normal_tools.get("allowed_tools") or []
    attack_success_tools: List[str] = attack_tools.get("attack_success_tools") or []

    # memory tools = normal allowed 중 baseline 제외 (보통 kb_search_trusted 1개)
    memory_tools = [t for t in normal_allowed if t not in set(baseline_tools)]

    selected_tools = _dedupe_keep_order(baseline_tools + memory_tools + attack_success_tools)

    # MCP 서버 실행 파라미터 (실행은 필요하지만, YAML에 경로/command는 기록하지 않음)
    normal_mcp = normal_tools.get("mcp_server") or {}
    attack_mcp = attack_tools.get("mcp_server") or {}

    normal_cmd = str(normal_mcp.get("command", "python"))
    normal_args = _abs_args(repo_root, normal_mcp.get("args") or [])

    attack_cmd = str(attack_mcp.get("command", "python"))
    attack_args = _abs_args(repo_root, attack_mcp.get("args") or [])

    # 두 서버에서 tool spec을 가져와 병합 (attack 쪽이 있으면 attack 우선)
    tools_from_normal = await _list_tools_from_mcp(normal_cmd, normal_args)
    tools_from_attack = await _list_tools_from_mcp(attack_cmd, attack_args)

    merged: Dict[str, Dict[str, Any]] = {}
    merged.update(tools_from_normal)
    merged.update(tools_from_attack)

    tool_specs: List[Dict[str, Any]] = []
    missing_tools: List[str] = []
    for name in selected_tools:
        if name in merged:
            tool_specs.append(merged[name])
        else:
            missing_tools.append(name)

    if missing_tools:
        raise RuntimeError(
            "선정된 도구 중 MCP list_tools()에서 스펙을 못 찾은 도구가 있습니다:\n"
            + "\n".join(missing_tools)
        )

    description = _infer_agent_description(system_prompt_text, fallback=agent_name)

    profile: Dict[str, Any] = {
        "agent_card": {
            "schema_version": "a2a.agent_card.v1",
            "id": agent_name,
            "name": agent_name,
            "description": description,
            "version": "0.1",
            "capabilities": {
                "input_modes": ["text"],
                "output_modes": ["text"],
            },
        },
        "red_teaming_profile": {
            "generated_at": _now_iso(),
            "system_prompt": system_prompt_text,
            "selected_tools": selected_tools,
            "tools": tool_specs,
        },
    }

    out_dir = repo_root / "red_teaming" / "agent_profiles" / agent_name / _today()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "agent_profile.yaml"

    with out_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(profile, f, sort_keys=False, allow_unicode=True)

    return profile, out_path


# ---------------------------
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("agent_name", help="예: ecommerce_operations_agent")
    ap.add_argument(
        "--repo-root",
        default=None,
        help="기본은 현재 파일 기준으로 repo root 자동 추정 (red_teaming/..). 필요시 직접 지정",
    )
    args = ap.parse_args()

    # 기본: 이 스크립트가 red_teaming/ 밑에 있다고 가정하고 repo root 추정
    if args.repo_root:
        repo_root = Path(args.repo_root).expanduser().resolve()
    else:
        repo_root = Path(__file__).resolve().parents[1]

    async def _run():
        _, out_path = await build_agent_profile(repo_root, args.agent_name)
        print(f"[OK] agent profile written: {out_path}")

    asyncio.run(_run())


if __name__ == "__main__":
    main()
