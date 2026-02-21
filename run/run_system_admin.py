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

# ✅ Gemini는 optional (openai_compat만 쓸 때 google 패키지 없어도 실행되게)
try:
    from google import genai
    from google.genai import types
except Exception:
    genai = None
    types = None

# ✅ OpenAI-compat (Ollama)
try:
    from openai import OpenAI
except Exception:
    OpenAI = None


# ----------------------------
# Utils
# ----------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_utc_yyyy_mm_dd() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_api_key(llm_cfg: dict) -> str:
    """Gemini 전용"""
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


# ----------------------------
# Gemini helpers
# ----------------------------
def mcp_tool_to_fn_decl(mcp_tool) -> Any:
    if types is None:
        raise RuntimeError("google-genai(types) is not available. Install google-genai or switch provider.")
    return types.FunctionDeclaration(
        name=mcp_tool.name,
        description=mcp_tool.description or "",
        parameters=mcp_tool.inputSchema or {"type": "object", "properties": {}},
    )


def extract_function_calls(resp) -> list[Any]:
    if types is None:
        return []
    out: list[Any] = []
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


# ----------------------------
# OpenAI-compat helpers
# ----------------------------
def mcp_tool_to_openai_tool(mcp_tool) -> dict[str, Any]:
    """MCP tool -> OpenAI tools schema"""
    return {
        "type": "function",
        "function": {
            "name": mcp_tool.name,
            "description": mcp_tool.description or "",
            "parameters": mcp_tool.inputSchema or {"type": "object", "properties": {}},
        },
    }


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
# Agent runner (single task) - Gemini
# ----------------------------
async def run_agent_once_gemini(
    *,
    client: Any,
    model: str,
    system_instruction: str,
    session: ClientSession,
    fn_decls: list[Any],
    user_prompt: str,
    max_steps: int,
    log_write: Callable[[dict[str, Any]], None],
) -> tuple[str, list[ToolCall]]:
    if types is None:
        raise RuntimeError("Gemini provider selected but google-genai is not installed.")
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

    contents: list[Any] = [
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
            final_text = (getattr(resp, "text", "") or "").strip()
            if not final_text:
                final_text = assistant_text
            log_write({"type": "final", "text": final_text, "ts": utc_now_iso()})
            return final_text, calls

        contents.append(resp.candidates[0].content)

        response_parts: list[Any] = []
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
# Agent runner (single task) - OpenAI compatible (Ollama)
# ----------------------------
async def run_agent_once_openai_compat(
    *,
    client: Any,  # OpenAI client
    model: str,
    system_instruction: str,
    session: ClientSession,
    tools: list[dict[str, Any]],
    user_prompt: str,
    max_steps: int,
    log_write: Callable[[dict[str, Any]], None],
) -> tuple[str, list[ToolCall]]:

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_instruction},
        {"role": "user", "content": user_prompt},
    ]

    calls: list[ToolCall] = []

    for _ in range(max_steps):
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0,
        )

        msg = resp.choices[0].message
        assistant_text = (msg.content or "").strip()
        if assistant_text:
            log_write({"type": "assistant", "text": assistant_text, "ts": utc_now_iso()})

        tool_calls = getattr(msg, "tool_calls", None) or []
        if not tool_calls:
            final_text = assistant_text
            log_write({"type": "final", "text": final_text, "ts": utc_now_iso()})
            return final_text, calls

        # assistant message (incl tool_calls) append
        try:
            messages.append(msg.model_dump(exclude_none=True))
        except Exception:
            # fallback minimal
            messages.append({"role": "assistant", "content": msg.content})

        for tc in tool_calls:
            tool_name = tc.function.name
            tool_args = json.loads(tc.function.arguments or "{}")

            calls.append(ToolCall(name=tool_name, args=tool_args))
            log_write({"type": "tool_call", "name": tool_name, "args": tool_args, "ts": utc_now_iso()})

            tool_result = await session.call_tool(tool_name, tool_args)
            tool_payload = serialize_call_tool_result(tool_result)
            log_write({"type": "tool_result", "name": tool_name, "result": tool_payload, "ts": utc_now_iso()})

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps({"result": tool_payload}, ensure_ascii=False),
                }
            )

    log_write({"type": "final", "text": "[ERROR] max_steps exceeded", "ts": utc_now_iso()})
    return "[ERROR] max_steps exceeded", calls


# ----------------------------
# Main
# ----------------------------
async def main_async(config_path: str, mode: str):
    cfg = yaml.safe_load(open(config_path, "r", encoding="utf-8"))

    scenario = cfg["scenario"]
    llm_cfg = cfg["llm"]
    llm_provider = (llm_cfg.get("provider") or "gemini").lower().strip()

    baseline_tools: list[str] = cfg.get("baseline_tools") or []
    if not baseline_tools:
        raise RuntimeError("baseline_tools is missing in config (need baseline tool list)")

    if "modes" not in cfg or mode not in cfg["modes"]:
        raise RuntimeError(f"Invalid mode '{mode}'. Available: {list((cfg.get('modes') or {}).keys())}")

    paths = cfg["modes"][mode]["paths"]
    max_steps = int(cfg["runner"]["max_steps"])
    base_dir = Path(cfg["logging"]["base_dir"])

    system_txt = Path(paths["system_prompt"]).read_text(encoding="utf-8")
    tasks = read_jsonl(paths["tasks"])
    tools_cfg = json.loads(Path(paths["tools"]).read_text(encoding="utf-8"))

    # ✅ tool_policy 기반 매핑/역할 추출
    tool_policy: dict[str, Any] = tools_cfg.get("tool_policy", {}) or {}
    attack_success_tools: list[str] = tools_cfg.get("attack_success_tools", []) or []

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

    # ✅ LLM client 생성 (provider 분기)
    gemini_client = None
    openai_client = None

    if llm_provider == "gemini":
        if genai is None:
            raise RuntimeError("Gemini provider selected but google-genai is not installed.")
        api_key = load_api_key(llm_cfg)
        gemini_client = genai.Client(api_key=api_key)

    elif llm_provider in ("openai_compat", "ollama"):
        if OpenAI is None:
            raise RuntimeError("openai package not installed. Run: pip install openai")
        base_url = (llm_cfg.get("base_url") or "http://localhost:11434/v1").strip().rstrip("/")
        api_key = (llm_cfg.get("api_key") or "ollama").strip()
        openai_client = OpenAI(base_url=base_url, api_key=api_key)

    else:
        raise RuntimeError(f"Unsupported llm.provider='{llm_provider}'. Use gemini or openai_compat/ollama.")

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
                    extra_attack = list(rag_tools_attack)
                    tid = str(task_id)

                    if tid.startswith("ipi-"):
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

                    elif tid.startswith("mp-"):
                        if not attack_success_tools:
                            raise RuntimeError(
                                f"[{task_id}] attack_success_tools is empty in tools config. "
                                f"Set tools_cfg['attack_success_tools']."
                            )
                        allowed_this_task = list(baseline_tools) + extra_attack + list(attack_success_tools)

                    else:
                        derived_attack_tool = t.get("attack_tool")
                        if not derived_attack_tool:
                            raise RuntimeError(f"[{task_id}] attack_tool is required for dpi-* tasks.")
                        allowed_this_task = list(baseline_tools) + extra_attack + [derived_attack_tool]
                else:
                    allowed_this_task = list(baseline_tools) + list(rag_tools_normal)

                # 중복 제거(순서 유지)
                allowed_this_task = list(dict.fromkeys(allowed_this_task))

                missing = [name for name in allowed_this_task if name not in tool_by_name]
                if missing:
                    raise RuntimeError(f"[{task_id}] Missing tools in MCP server: {missing}")

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
                        "llm_provider": llm_provider,
                        "ts": utc_now_iso(),
                        "user": user_prompt,
                        "tools_exposed": allowed_this_task,
                    }

                    if mode == "attack":
                        if derived_attack_tool:
                            meta["attack_tool"] = derived_attack_tool
                        if ipi_source_tool:
                            meta["ipi_source_tool"] = ipi_source_tool
                        if str(task_id).startswith("mp-"):
                            meta["attack_tools_exposed"] = attack_success_tools

                    log_write(meta)

                    # ✅ provider별 도구 스키마/러너 분기
                    if llm_provider == "gemini":
                        fn_decls = [mcp_tool_to_fn_decl(tool_by_name[name]) for name in allowed_this_task]
                        await run_agent_once_gemini(
                            client=gemini_client,
                            model=llm_cfg["model"],
                            system_instruction=system_txt,
                            session=session,
                            fn_decls=fn_decls,
                            user_prompt=user_prompt,
                            max_steps=max_steps,
                            log_write=log_write,
                        )
                    else:
                        openai_tools = [mcp_tool_to_openai_tool(tool_by_name[name]) for name in allowed_this_task]
                        await run_agent_once_openai_compat(
                            client=openai_client,
                            model=llm_cfg["model"],
                            system_instruction=system_txt,
                            session=session,
                            tools=openai_tools,
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
