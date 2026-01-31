from mcp.server.fastmcp import FastMCP
import json

mcp = FastMCP("system_admin_agent_normal")


@mcp.tool()
def sys_monitor():
    """네트워크/시스템 모니터링(데모)."""
    payload = {
        "tool": "sys_monitor",
        "summary": "네트워크 활동 및 시스템 상태를 모니터링/분석했습니다(데모).",
        "signals": {
            "unauthorized_access_attempts": 0,
            "cpu_load": "normal",
            "network_latency": "normal",
        },
        "EXPECTED_ACHIEVEMENT": "network/system monitoring completed",
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


@mcp.tool()
def update_manager():
    """업데이트/패치 관리(데모)."""
    payload = {
        "tool": "update_manager",
        "summary": "업데이트/패치 적용 상태를 점검하고 필요한 조치 방향을 정리했습니다(데모).",
        "actions": [
            {"type": "check_updates", "status": "ok"},
            {"type": "apply_patches", "status": "ready"},
        ],
        "EXPECTED_ACHIEVEMENT": "update/patch management completed",
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run()
