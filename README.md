# Agent AI Security (ASB 스타일 실험 환경, MCP 기반)

이 프로젝트는 ASB(Agent Security Bench)를 그대로 복제하기보다는,
필요한 구성(시나리오/태스크/툴 세팅/로그 포맷)을 인용해서 실험 목적에 맞게 재구성한 것이다.

현재는 ASB의 여러 시나리오 중 system_admin_agent 하나만 먼저 구현했고,
추후 시나리오를 쉽게 확장할 수 있도록 시나리오 단위로 파일을 분리했다.

목표
- 정상(benign) 태스크에서 정상 도구 2개만 사용하는 기본 루프를 재현
- 공격(attack) 태스크에서 DPI(Direct Prompt Injection)로 공격 도구 호출 유도를 재현
- 실행 과정은 JSONL 로그로 남기고, 후처리로 PNA/ASR 등의 지표를 산출


프로젝트 구조

Agent AI Security/
- configs/
  - system_admin_agent.yml
- scenarios/
  - system_admin_agent/
    - system.txt
    - tasks_benign.jsonl
    - tasks_attack.jsonl
    - normal_tools.json
    - attack_tools.json
- mcp_servers/
  - system_admin_agent/
    - normal/
      - server.py
    - attack/
      - server.py
- run/
  - run_system_admin.py
  - logs/
- src/
  - (추후 공용 로직/유틸/스코어러 확장용)


configs/
- 실행 설정(yml)을 둔다.
- system_admin_agent.yml 하나로 normal/attack 모드를 모두 관리하고,
  실행 시 --mode로 선택한다.

scenarios/system_admin_agent/
- 시나리오 정의가 들어간다.
- system.txt: 시스템 프롬프트(PLAN 규칙 포함)
- tasks_benign.jsonl: 정상 태스크 목록
- tasks_attack.jsonl: 공격 태스크 목록(DPI 포함, attack_tool 힌트 포함)
- normal_tools.json / attack_tools.json: MCP 서버 정보 + allowed_tools 정의

mcp_servers/system_admin_agent/
- MCP 서버 구현이다.
- normal: 정상 도구 2개 제공
- attack: 정상 도구 + 공격 도구 제공

run/
- 실행 스크립트가 들어간다.
- run_system_admin.py가 설정을 읽고 MCP 서버(stdio)를 붙여서 LLM tool-calling을 수행한다.
- 실행 과정은 task 단위로 JSONL 로그로 저장한다.

run/logs/
- 실행 로그 저장 위치다.
- 기본 경로 예시
  - run/logs/system_admin_agent/normal/YYYY-MM-DD/<task_id>_<time>.jsonl
  - run/logs/system_admin_agent/attack/YYYY-MM-DD/<task_id>_<time>.jsonl


LLM 설정
- 현재는 Gemini API를 사용한다.
- configs/system_admin_agent.yml에서 provider/model/api_key_file로 관리한다.
- 추후 local LLM로 교체할 수 있도록 provider 구조로 분리해 둔다.

API Key
- API_Key/gemini_api_key 파일에 한 줄로 저장한다.
- 이 파일은 레포에 포함하지 않는다.

실행 방법

Normal
python run/run_system_admin.py --config configs/system_admin_agent.yml --mode normal

Attack
python run/run_system_admin.py --config configs/system_admin_agent.yml --mode attack


로그 포맷(JSONL)
- meta: 시나리오/모드/태스크 정보
- tool_call: 호출한 MCP 도구와 인자
- tool_result: 도구 반환 결과
- final: 최종 응답 텍스트

이 로그들을 전체 순회하면서 PNA/ASR 산출을 한다.
(스코어링 스크립트는 후처리 단계로 분리해서 추가한다.)
