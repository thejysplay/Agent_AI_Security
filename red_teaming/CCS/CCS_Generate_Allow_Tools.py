#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CCS 전용 allow_tool.json 생성기.
각 agent의 MCP 서버에 직접 연결하여 도구 목록을 받아온 뒤
generated_tasks/{agent}/{date}/allow_tool.json 을 생성한다.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def repo_root_from_this_file() -> Path:
    return Path(__file__).resolve().parents[2]


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Agent / date discovery
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def discover_agents(agent_profiles_dir: Path) -> List[str]:
    if not agent_profiles_dir.exists():
        return []
    agents = []
    for d in sorted(agent_profiles_dir.iterdir()):
        if d.is_dir() and not d.name.startswith("."):
            agents.append(d.name)
    return agents


def get_latest_profile_date(agent_profiles_dir: Path, agent: str) -> Optional[str]:
    base = agent_profiles_dir / agent
    if not base.exists():
        return None
    dates = []
    for d in sorted(base.iterdir()):
        if d.is_dir() and re.match(r"^\d{4}-\d{2}-\d{2}$", d.name):
            dates.append(d.name)
    return dates[-1] if dates else None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MCP 서버 연결 → 도구 목록 fetch
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def fetch_tools_from_mcp(
    server_path: Path,
    python_executable: str,
) -> List[Dict[str, Any]]:
    """MCP 서버에 연결하여 도구 이름 + description을 가져온다."""
    params = StdioServerParameters(
        command=python_executable,
        args=[str(server_path)],
        env=os.environ.copy(),
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            raw_tools = getattr(result, "tools", []) or []

    tools = []
    for t in raw_tools:
        tools.append({
            "name": t.name,
            "description": getattr(t, "description", "") or "",
        })
    return tools


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# allow_tool.json 생성
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def classify_tool_role(name: str, description: str) -> Dict[str, str]:
    """도구명과 description으로 role/trust_level을 자동 분류한다."""
    n = name.lower()
    d = description.lower()

    if "kb_search" in n or "kb" in n and "검색" in d:
        return {"role": "rag", "trust_level": "trusted_internal_kb"}

    return {"role": "baseline", "trust_level": "trusted_internal"}


def build_allow_tool_data(
    agent: str,
    tools: List[Dict[str, Any]],
) -> Dict[str, Any]:
    tool_names = [t["name"] for t in tools]

    tool_policy = {}
    for t in tools:
        policy = classify_tool_role(t["name"], t["description"])
        tool_policy[t["name"]] = policy

    return {
        "mcp_server": {
            "command": "python",
            "args": [f"mcp_servers/CCS/{agent}/server.py"]
        },
        "allowed_tools": tool_names,
        "tool_policy": tool_policy,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 단일 agent 처리
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def process_one_agent(
    *,
    repo_root: Path,
    agent: str,
    profile_date: str,
    python_executable: str,
) -> Path:
    server_path = repo_root / "mcp_servers" / "CCS" / agent / "server.py"
    if not server_path.exists():
        raise FileNotFoundError(f"server.py not found: {server_path}")

    # MCP 서버 연결 → 도구 목록
    tools = await fetch_tools_from_mcp(server_path, python_executable)

    if not tools:
        raise RuntimeError(f"MCP 서버에서 도구를 가져오지 못함: {agent}")

    # allow_tool.json 생성
    data = build_allow_tool_data(agent, tools)

    out_dir = repo_root / "red_teaming" / "CCS" / "generated_tasks" / agent / profile_date
    ensure_dir(out_dir)

    out_path = out_dir / "allow_tool.json"
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    return out_path


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# main
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def async_main() -> int:
    parser = argparse.ArgumentParser(description="CCS allow_tool.json 일괄 생성 (MCP 서버 연결)")
    parser.add_argument("--agent", default="", help="특정 agent만 처리. 미지정 시 전체.")
    parser.add_argument("--date", default="", help="profile 날짜. 미지정 시 최신 자동 선택.")
    parser.add_argument("--repo-root", default="", help="프로젝트 루트. 미지정 시 자동 탐지.")
    parser.add_argument("--python", default=sys.executable, help="MCP server.py 실행에 사용할 Python 경로.")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).expanduser() if args.repo_root.strip() else repo_root_from_this_file()
    agent_profiles_dir = repo_root / "red_teaming" / "CCS" / "agent_profiles"

    if not agent_profiles_dir.exists():
        print(f"[ERROR] agent_profiles_dir not found: {agent_profiles_dir}")
        return 1

    # agent 목록
    if args.agent.strip():
        agents = [args.agent.strip()]
    else:
        agents = discover_agents(agent_profiles_dir)
        if not agents:
            print(f"[ERROR] No agents found in {agent_profiles_dir}")
            return 1

    print(f"{'='*60}")
    print(f"CCS allow_tool.json 생성 (MCP 서버 연결)")
    print(f"  agents: {len(agents)}개")
    print(f"  python: {args.python}")
    print(f"{'='*60}\n")

    ok = 0
    fail = 0

    for agent in agents:
        # 날짜 결정
        if args.date.strip():
            date = args.date.strip()
        else:
            date = get_latest_profile_date(agent_profiles_dir, agent)

        if not date:
            print(f"[SKIP] {agent}: profile date 없음")
            fail += 1
            continue

        try:
            out_path = await process_one_agent(
                repo_root=repo_root,
                agent=agent,
                profile_date=date,
                python_executable=args.python,
            )

            # 검증: 도구 수 출력
            data = json.loads(out_path.read_text(encoding="utf-8"))
            n_tools = len(data.get("allowed_tools", []))
            tool_names = ", ".join(data.get("allowed_tools", []))

            print(f"[OK] {agent} ({date}): {n_tools}개 도구")
            print(f"     → {out_path}")
            print(f"     도구: {tool_names}\n")
            ok += 1

        except Exception as e:
            print(f"[ERROR] {agent}: {e}\n")
            fail += 1

    print(f"{'='*60}")
    print(f"완료: success={ok}, fail={fail}, total={len(agents)}")

    return 0 if fail == 0 else 1


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()