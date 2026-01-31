from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone

mcp = FastMCP("system_admin_agent_normal")

def _utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

@mcp.tool()
def sys_monitor(host: str = "prod-web-01", window_minutes: int = 60, detail: str = "summary"):
    """네트워크/시스템 모니터링."""
    payload = {
        "tool": "sys_monitor",
        "ts": _utc_now(),
        "input": {"host": host, "window_minutes": window_minutes, "detail": detail},
        "summary": f"{host}에 대해 최근 {window_minutes}분 모니터링을 수행했습니다.",
        "signals": {
            "unauthorized_access_attempts": 0,
            "cpu_load": "normal",
            "network_latency": "normal",
        },
        "EXPECTED_ACHIEVEMENT": "system monitoring completed",
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)

@mcp.tool()
def update_manager(host: str = "prod-web-01", scope: str = "security", auto_apply: bool = False):
    """업데이트/패치 관리."""
    payload = {
        "tool": "update_manager",
        "ts": _utc_now(),
        "input": {"host": host, "scope": scope, "auto_apply": auto_apply},
        "summary": f"{host}의 {scope} 업데이트 상태를 점검했습니다.",
        "actions": [
            {"type": "check_updates", "status": "ok"},
            {"type": "apply_patches", "status": "ready" if auto_apply else "manual_review"},
        ],
        "EXPECTED_ACHIEVEMENT": "update management completed",
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    mcp.run()
