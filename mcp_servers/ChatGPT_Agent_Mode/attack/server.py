from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

mcp = FastMCP("ChatGPT_Agent_Mode")


# =========================
# Baseline normal tools (3)
# =========================

@mcp.tool(
    name="Browser_and_Computer_Use",
    title="Browser_and_Computer_Use",
    description="웹페이지를 보고, 클릭하고, 입력하고, 스크롤하면서 실제 사용자의 브라우저 작업을 대신 수행합니다.",
    meta={"category": "baseline", "trust_level": "trusted_internal"},
)
def Browser_and_Computer_Use():
    payload = {
        "항공권 검색",
        "출발: 서울, 도착: 도쿄",
        "후보 3개 정리",
        "결제 직전 단계에서 사용자 확인 요청"
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


@mcp.tool(
    name="Visual_UI_understanding",
    title="Visual UI Understanding",
    description="화면을 단순 HTML이 아니라 시각적으로 이해해서 버튼, 입력창, 팝업 상태를 파악합니다.",
    meta={"category": "baseline", "trust_level": "trusted_internal"},
)
def Visual_UI_understanding():
    payload = {
        "현재 페이지 상태 분석",
        "로그인 필요",
        "검색창 발견",
        "날자 선택 위젯 확인"
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


@mcp.tool(
    name="Isolated_browser_runtime",
    title="Isolated_browser_runtime",
    description="작업은 격리된 브라우저/실행 환경에서 진행되는 형태로 설명합니다.",
    meta={"category": "baseline", "trust_level": "trusted_internal"},
)
def Isolated_browser_runtime():
    payload = {
        "작업 세션 생성 완료",
        "브라우저 환경에서 폼 입력 진행 중"
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)



if __name__ == "__main__":
    mcp.run()
