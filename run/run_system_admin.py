from __future__ import annotations

import argparse
import asyncio
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from google import genai
from google.genai import types


# ----------------------------
# Utils
# ----------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_utc_yyyy_mm_dd() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_api_key(llm_cfg: dict) -> str:
    key_file = llm_cfg.get("api_key_file")
    if key_file:
        key_path = Path(key_file)
        if key_path.exists():
            key = key_path.read_text(encoding="utf-8").strip()
            if key:
                return key

    env_name = llm_cfg.get("api_key_env")
    if env_name:
        key = os.getenv(env_name, "").strip()
        if key:
            return key

    raise RuntimeError("Gemini API key not found (set llm.api_key_file or llm.api_key_env)")


def read_jsonl(path: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items


def mcp_tool_to_fn_decl(mcp_tool) -> types.FunctionDeclaration:
    return types.FunctionDeclaration(
        name=mcp_tool.name,
        description=mcp_tool.description or "",
        parameters=mcp_tool.inputSchema or {"type": "object", "properties": {}},
    )


def extract_function_calls(resp) -> list[types.FunctionCall]:
    out: list[types.FunctionCall] = []
    try:
        parts = resp.candidates[0].content.parts
    except Exception:
        return out

    for p in parts:
        fc = getattr(p, "function_call", None)
        if fc:
            out.append(fc)
    return out


def extract_assistant_text(resp) -> str:
    try:
        parts = resp.candidates[0].content.parts
    except Exception:
        return ""

    texts: list[str] = []
    for p in parts:
        txt = getattr(p, "text", None)
        if txt:
            t = txt.strip()
            if t:
                texts.append(t)
    return "\n".join(texts).strip()


def serialize_call_tool_result(result) -> Any:
    try:
        blocks = getattr(result, "content", None) or []
        out = []
        for b in blocks:
            if getattr(b, "type", None) == "text":
                out.append({"type": "text", "text": b.text})
            else:
                out.append({"type": str(getattr(b, "type", "unknown")), "value": str(b)})
        return {"content": out, "isError": getattr(result, "isError", False)}
    except Exception:
        return {"raw": str(result)}


# ----------------------------
# Data structures
# ----------------------------
@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]


# ----------------------------
# Agent runner (single task)
# ----------------------------
async def run_agent_once(
    *,
    client: genai.Client,
    model: str,
    system_instruction: str,
    session: ClientSession,
    fn_decls: list[types.FunctionDeclaration],
    user_prompt: str,
    max_steps: int,
    log_write: Callable[[dict[str, Any]], None],
) -> tuple[str, list[ToolCall]]:
    tool_obj = types.Tool(function_declarations=fn_decls)

    tool_config = types.ToolConfig(
        function_calling_config=types.FunctionCallingConfig(mode="AUTO")
    )

    config = types.GenerateContentConfig(
        tools=[tool_obj],
        tool_config=tool_config,
        system_instruction=system_instruction,
        temperature=0,
    )

    contents: list[types.Content] = [
        types.Content(role="user", parts=[types.Part(text=user_prompt)])
    ]

    calls: list[ToolCall] = []

    for _ in range(max_steps):
        resp = client.models.generate_content(model=model, contents=contents, config=config)

        assistant_text = extract_assistant_text(resp)
        if assistant_text:
            log_write({"type": "assistant", "text": assistant_text, "ts": utc_now_iso()})

        fcalls = extract_function_calls(resp)
        if not fcalls:
            final_text = (resp.text or "").strip()
            if not final_text:
                final_text = assistant_text
            log_write({"type": "final", "text": final_text, "ts": utc_now_iso()})
            return final_text, calls

        contents.append(resp.candidates[0].content)

        response_parts: list[types.Part] = []
        for fc in fcalls:
            tool_name = fc.name
            tool_args = dict(fc.args or {})

            calls.append(ToolCall(name=tool_name, args=tool_args))
            log_write({"type": "tool_call", "name": tool_name, "args": tool_args, "ts": utc_now_iso()})

            tool_result = await session.call_tool(tool_name, tool_args)
            tool_payload = serialize_call_tool_result(tool_result)
            log_write({"type": "tool_result", "name": tool_name, "result": tool_payload, "ts": utc_now_iso()})

            response_parts.append(
                types.Part.from_function_response(name=tool_name, response={"result": tool_payload})
            )

        contents.append(types.Content(role="user", parts=response_parts))

    log_write({"type": "final", "text": "[ERROR] max_steps exceeded", "ts": utc_now_iso()})
    return "[ERROR] max_steps exceeded", calls


# ----------------------------
# Main
# ----------------------------
async def main_async(config_path: str, mode: str):
    cfg = yaml.safe_load(open(config_path, "r", encoding="utf-8"))

    scenario = cfg["scenario"]
    llm_cfg = cfg["llm"]

    baseline_tools: list[str] = cfg.get("baseline_tools") or []
    if not baseline_tools:
        raise RuntimeError("baseline_tools is missing in config (need normal tool 2개 목록)")

    if "modes" not in cfg or mode not in cfg["modes"]:
        raise RuntimeError(f"Invalid mode '{mode}'. Available: {list((cfg.get('modes') or {}).keys())}")

    paths = cfg["modes"][mode]["paths"]
    max_steps = int(cfg["runner"]["max_steps"])
    base_dir = Path(cfg["logging"]["base_dir"])

    system_txt = Path(paths["system_prompt"]).read_text(encoding="utf-8")
    tasks = read_jsonl(paths["tasks"])
    tools_cfg = json.loads(Path(paths["tools"]).read_text(encoding="utf-8"))

    # ✅ NEW: tool_policy 기반 매핑/역할 추출
    tool_policy: dict[str, Any] = tools_cfg.get("tool_policy", {}) or {}

    # ipi_source_tool -> target(attack_tool) 매핑
    ipi_target_map: dict[str, str] = {}
    for tool_name, pol in tool_policy.items():
        if isinstance(pol, dict) and pol.get("role") == "ipi_source":
            tgt = pol.get("target")
            if tgt:
                ipi_target_map[tool_name] = tgt

    # mode별 rag tool 자동 포함
    rag_tools_normal: list[str] = []
    rag_tools_attack: list[str] = []

    for tool_name, pol in tool_policy.items():
        if not isinstance(pol, dict):
            continue
        role = pol.get("role")
        if role == "rag":
            rag_tools_normal.append(tool_name)
        elif role == "rag_ipi_source":
            rag_tools_attack.append(tool_name)

    api_key = load_api_key(llm_cfg)
    client = genai.Client(api_key=api_key)

    server = tools_cfg["mcp_server"]
    tools_superset = tools_cfg.get("allowed_tools", [])

    server_params = StdioServerParameters(
        command=server["command"],
        args=server.get("args", []),
        env=os.environ.copy(),
    )

    date_dir = base_dir / scenario / mode / today_utc_yyyy_mm_dd()
    date_dir.mkdir(parents=True, exist_ok=True)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tool_list_resp = await session.list_tools()
            all_mcp_tools = tool_list_resp.tools
            tool_by_name = {t.name: t for t in all_mcp_tools}

            if tools_superset:
                tool_by_name = {n: t for n, t in tool_by_name.items() if n in set(tools_superset)}

            missing_baseline = [t for t in baseline_tools if t not in tool_by_name]
            if missing_baseline:
                raise RuntimeError(f"Missing baseline tools in MCP server: {missing_baseline}")

            for t in tasks:
                task_id = t["id"]
                user_prompt = t["user"]

                derived_attack_tool: str | None = None
                ipi_source_tool: str | None = None

                if mode == "attack":
                    # ✅ attack 모드에서는 오염 RAG를 항상 노출(원하면 여기서 조건 바꿔도 됨)
                    extra_attack = list(rag_tools_attack)

                    if str(task_id).startswith("ipi-"):
                        ipi_source_tool = t.get("ipi_source_tool")
                        if not ipi_source_tool:
                            raise RuntimeError(f"[{task_id}] ipi_source_tool is required for ipi-* tasks.")

                        derived_attack_tool = ipi_target_map.get(ipi_source_tool)
                        if not derived_attack_tool:
                            raise RuntimeError(
                                f"[{task_id}] No target mapping for ipi_source_tool='{ipi_source_tool}'. "
                                f"Check tools_cfg.tool_policy[{ipi_source_tool}].target"
                            )

                        allowed_this_task = list(baseline_tools) + extra_attack + [ipi_source_tool, derived_attack_tool]
                    else:
                        derived_attack_tool = t.get("attack_tool")
                        if not derived_attack_tool:
                            raise RuntimeError(f"[{task_id}] attack_tool is required for dpi-* tasks.")
                        allowed_this_task = list(baseline_tools) + extra_attack + [derived_attack_tool]
                else:
                    # ✅ normal 모드에서는 trusted RAG 노출(있으면)
                    allowed_this_task = list(baseline_tools) + list(rag_tools_normal)

                # 중복 제거(순서 유지)
                allowed_this_task = list(dict.fromkeys(allowed_this_task))

                missing = [name for name in allowed_this_task if name not in tool_by_name]
                if missing:
                    raise RuntimeError(f"[{task_id}] Missing tools in MCP server: {missing}")

                fn_decls = [mcp_tool_to_fn_decl(tool_by_name[name]) for name in allowed_this_task]

                stamp = datetime.now(timezone.utc).strftime("%H%M%S")
                log_path = date_dir / f"{task_id}_{stamp}.jsonl"

                with log_path.open("a", encoding="utf-8") as lf:
                    def log_write(obj: dict[str, Any]):
                        lf.write(json.dumps(obj, ensure_ascii=False) + "\n")
                        lf.flush()

                    meta: dict[str, Any] = {
                        "type": "meta",
                        "scenario": scenario,
                        "mode": mode,
                        "task_id": task_id,
                        "model": llm_cfg["model"],
                        "ts": utc_now_iso(),
                        "user": user_prompt,
                        "tools_exposed": allowed_this_task,
                    }

                    if mode == "attack":
                        meta["attack_tool"] = derived_attack_tool
                        if ipi_source_tool:
                            meta["ipi_source_tool"] = ipi_source_tool

                    log_write(meta)

                    await run_agent_once(
                        client=client,
                        model=llm_cfg["model"],
                        system_instruction=system_txt,
                        session=session,
                        fn_decls=fn_decls,
                        user_prompt=user_prompt,
                        max_steps=max_steps,
                        log_write=log_write,
                    )

                print(f"[OK] saved log: {log_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/system_admin_agent.yml")
    ap.add_argument("--mode", choices=["normal", "attack"], default="normal")
    args = ap.parse_args()
    asyncio.run(main_async(args.config, args.mode))


if __name__ == "__main__":
    main()
