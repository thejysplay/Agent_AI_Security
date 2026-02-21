# Agent_AI_Security — Simulation Testbed & Red Teaming

이 저장소는 LLM 기반 Agent를 대상으로, 동일한 Agent 루프/러너에서 **정상(Benign) vs 공격(Attack)** 을 재현하고, 생성된 **실행 Trace(JSONL 로그)** 를 기반으로 후속 평가(판정/오라클)를 수행할 수 있도록 만든 **모사환경(Simulation Testbed)** + **레드팀(Red Teaming) 파이프라인** 입니다.

큰 구성은 2가지입니다.

1. **모사환경(Simulation Testbed)**: 도메인별 Agent, 도구(MCP), 정상/공격 Task, KB(RAG/LTM)까지 포함한 실행 환경
2. **레드팀(Red Teaming)**: Agent Profile + Technique DB를 기반으로 **공격 Task(JSONL)** 를 생성하고, Red Team 실행을 위한 **도구 노출 세트(8개)** 를 재구성하는 생성 파이프라인

> **KB = LTM (표현 고정)**
>
> 이 저장소에서의 KB는 **LTM-backed operational KB (RAG)**, 즉 **문서 기반 Long-term Memory(LTM)** 를 모델링합니다.
> 에이전트는 필요할 때 `kb_search_*` 도구를 호출해 LTM을 조회하고, 검색 결과 payload가 컨텍스트로 주입되어 다음 행동(추론/도구 호출/최종 답변)에 영향을 줍니다.

---

# 1) 모사환경 (Simulation Testbed)

## 1.1 목적

* 동일한 Agent 실행 루프(러너)에서 **정상 vs 공격**을 조건만 바꿔 비교 가능하게 만들기
* 공격 유형별 “유도 경로”를 분리해서 재현 가능하게 만들기

  * **DPI**: 사용자 입력(prompt) 자체에 악성 지시를 직접 섞어 주입
  * **IPI**: 외부 소스(티켓/벤더/문서 등)를 조회하도록 유도 → 그 결과(payload)에 악성 지시가 포함되어 간접 주입
  * **MP**: KB/RAG(LTM) 자체가 오염되어 검색 결과가 공격을 유도
* 모든 실행은 Trace로 남음

  * “무슨 입력 → 어떤 도구 노출 → 어떤 호출/결과 → 최종 출력”이 JSONL로 기록되어, 나중에 판정/오라클 적용 가능

---

## 1.2 실험 단위: Domain Agent(Scenario)

* 도메인(시나리오) 단위로 독립된 Agent가 존재
* 예: `system_admin_agent`, `ecommerce_operations_agent`, `hr_agent`, `travel_agent`, `finance_agent`
* **총 5개 도메인** 운영을 기본 전제로 함

> 도메인은 “업무 맥락 + 정상 도구 + 고위험 도구 + 외부 IPI 소스 + KB(LTM)”가 한 세트로 묶인 독립 실험 단위

---

## 1.3 Task 세트 구성 (도메인 1개 기준)

도메인 1개는 아래 Task 세트를 가집니다.

| TASK 유형    | 설명                              | 개수(도메인당) | 전체(5도메인) |
| ---------- | ------------------------------- | -------: | -------: |
| 정상(Benign) | 정상 업무 목표만 포함                    |       50 |      250 |
| 공격(DPI)    | 정상 TASK에 직접 프롬프트 주입 결합          |       50 |      250 |
| 공격(IPI)    | 오염된 외부 소스(문서/티켓/벤더 등) 조회로 간접 주입 |       50 |      250 |
| 공격(MP)     | 오염된 KB/RAG(LTM)로 감염 유도          |       50 |      250 |
| 악성 합계      | DPI+IPI+MP                      |      150 |      750 |
| 총합         | 정상 50 + 악성 150                  |      200 |    1,000 |

### Task 파일 위치(예시)

* `scenarios/<agent>/tasks_benign.jsonl`
* `scenarios/<agent>/tasks_attack.jsonl`

### Task JSONL 스키마(기본)

```json
{"id":"benign-001","user":"주문 ORD-... 상태 확인 후 상담노트 남겨줘"}
{"id":"ipi-001","user":"외부 운영 문서 확인 후 조치 요약해줘","ipi_source_tool":"..."}
{"id":"mp-001","user":"정책 검색 기반으로 조치해줘"}
```

> 러너는 Task JSON에 추가 키가 있어도 무시합니다. (예: `technique_id`, `oracle`, `risk` 같은 메타를 같이 넣어도 실행에는 영향 없음)

---

## 1.4 Tool(도구) 구성 (도메인 1개 기준)

도구는 “정상 수행 도구”와 “공격 유도/성공 도구”로 분리됩니다.

| Tool 그룹        | 설명                            | 개수(도메인당) | 비고                        |
| -------------- | ----------------------------- | -------: | ------------------------- |
| Baseline 정상 도구 | 정상 업무 수행에 필요한 핵심 기능           |        5 | 도메인별로 다름                  |
| 정상 RAG 도구      | Trusted KB(LTM) 검색            |        1 | `kb_search_trusted` 같은 형태 |
| 정상 도구 합계       |                               |        6 | 5 + 1                     |
| 공격 성공 도구(고위험)  | 공격자가 궁극적으로 실행시키려는 도구          |        2 | `attack_success_tools`    |
| IPI source 도구  | 외부 소스 “도구화”(벤더/티켓/메일/웹 등)     |       50 | 예: vendor 25 + ticket 25  |
| 오염 RAG 도구      | Poisoned/Untrusted KB(LTM) 검색 |        1 | `*_kb_search_untrusted`   |
| 악성 도구 풀 합계     |                               |       53 | 2 + 50 + 1                |

> 핵심 아이디어: **공격 실행(성공) 도구는 2개로 고정**하고, “어떤 경로(DPI/IPI/MP)로 그 도구를 실행시키는가”를 다양한 Task로 실험합니다.

---

## 1.5 KB(문서/메모리=LTM) 구성 (도메인 1개 기준)

KB는 “정상(Trusted)”과 “오염(Poisoned/Untrusted)”로 분리합니다.

| KB 유형            | 설명                       | 권장 개수(도메인당) | 비고                 |
| ---------------- | ------------------------ | ----------: | ------------------ |
| Trusted KB docs  | 정상 근거 문서(정책/매뉴얼/SOP/FAQ) |          20 | 운영 근거              |
| Poisoned KB docs | 오염된 문서(주입/편향/유도 포함)      |          20 | Trusted와 1:1 대응 추천 |
| KB 합계            |                          |          40 | 20 + 20            |

예시 위치:

* `scenarios/<agent>/KB/trusted/...`
* `scenarios/<agent>/KB/poisoned/...` 또는 `KB/untrusted/...`

---

## 1.6 Runner(실행기): 어떻게 “모사환경 실행”을 돌리나

러너(예: `run/run_ecomerce.py`)는 아래 순서로 동작합니다.

1. **Config 읽기**

* `scenario`: 도메인 id
* `baseline_tools`: 정상 핵심 도구 5개 목록(존재 검증용)
* `modes.normal.paths`: `system_prompt / tasks / tools` 경로
* `modes.attack.paths`: `system_prompt / tasks / tools` 경로
* `logging.base_dir`: 로그 출력 베이스 디렉토리
* `runner.max_steps`: 툴 호출 최대 루프 횟수

2. **mode 선택**

* `--mode normal` 또는 `--mode attack`
* mode에 따라 tasks/tools/system_prompt 로드 경로가 바뀜

3. **LLM 루프 실행 + MCP 도구 호출**

* 노출된 도구 스키마(allowed_tools)를 기반으로 tool-call 수행

4. **Trace(JSONL) 저장**

* `<base_dir>/<scenario>/<mode>/<YYYY-MM-DD>/<task_id>_<HHMMSS>.jsonl`
* 이벤트 예: `meta`, `assistant(PLAN 포함)`, `tool_call`, `tool_result`, `final`

### 모사환경 실행 예시

(도메인 러너 파일 이름은 `run/` 폴더의 runner를 사용)

```bash
# normal 모드
python run/run_ecomerce.py --config "configs/ecommerce_operations_agent.yml" --mode normal

# attack 모드(모사 공격: DPI/IPI/MP task 포함)
python run/run_ecomerce.py --config "configs/ecommerce_operations_agent.yml" --mode attack
```

---

# 2) 레드팀 (Red Teaming)

레드팀은 모사환경과 “완전히 별개로 따로 노는 시스템”이 아니라,
**모사환경 위에 얹히는 생성 레이어**입니다.

* 모사환경은 “실행/로그 인프라(러너, MCP 서버, Trace 포맷)”를 제공합니다.
* 레드팀은 그 인프라를 활용해, 사람이 수동으로 공격 Task를 쓰지 않아도 되게끔
  **Profile + Technique DB 기반으로 공격 Task를 생성**하고, 실행을 위한 **도구 노출 세트(8개)** 를 재구성합니다.

즉, 둘의 관계는 이렇게 정리됩니다.

* **모사환경**: 실행기/도메인 환경/로그 표준
* **레드팀**: 공격 벤치(입력) 생성 + 실행 세팅 자동화

---

## 2.1 레드팀의 목적

* “공격 Task”를 사람이 일일이 쓰지 않고,

  * Agent Profile(도구/정책/프롬프트 요약) +
  * Technique DB(공격 목표/벡터/오라클 정의)
    를 기반으로 LLM이 공격 시나리오(Task JSONL)를 생성하게 함
* 생성된 Task는 **기존 러너를 그대로 사용해 실행**
* 판정(성공/실패)은 **실행 후 로그 기반**으로 별도 수행(오라클 적용)

---

## 2.2 red_teaming 디렉토리 구조

`red_teaming/`은 “기존 모사환경 위에 얹는” 별도 레이어입니다.

권장 구조:

```
red_teaming/
  technique_db/
    AI Red Teaming - Agent Red Team Technique DB.csv
  agent_profiles/
    <agent>/
      <YYYY-MM-DD>/
        agent_profile.yaml
  generated_tasks/
    <agent>/
      <YYYY-MM-DD>/
        tasks_attack.jsonl
        redteam_tools.json
  generate_agent_profile.py
  generate_redteam_scenarios.py
  run/
    logs/
```

---

## 2.3 Technique DB(공격 테크닉 DB)

Technique DB는 “도메인 종속 X”로 공유 가능한 형태로 유지합니다.

CSV 컬럼(고정 예):

* `attack_objective`
* `attack_vector`
* `technique_id`
* `target_surface`
* `action_intent`
* `oracle_type`
* `oracle`
* `risk(impact/likelihood)`
* `notes/ref (OWASP 매핑)`

이 DB는 레드티밍 LLM이 어떤 테크닉으로 시나리오를 만들지 선택하는 후보 풀입니다.

---

## 2.4 Agent Profile(에이전트 프로파일) 생성

Agent Profile은 레드티밍 LLM이 “이 Agent가 어떤 도구를 가지고, 어떤 역할/제약을 갖는지”를 알기 위한 입력입니다.

기본 위치:

* `red_teaming/agent_profiles/<agent>/<YYYY-MM-DD>/agent_profile.yaml`

포함되는 핵심 정보(요약):

* `agent_card`: A2A Agent Card 기반 메타(최소한의 식별/설명)
* `red_teaming_profile.system_prompt`: `system.txt`를 읽어 들어간 내용(제약/TRACE RULE 포함)
* `red_teaming_profile.selected_tools`: 레드티밍에서 사용할 도구 8개(아래 2.5의 결과와 정합)

---

## 2.5 Red Team Tools JSON 생성 (redteam_tools.json)

러너가 attack 모드에서 읽는 `paths.tools`는 “파일 경로”를 기대합니다.

따라서 레드티밍 실행을 위해 도메인별 전용 tools json이 필요합니다.

출력 위치(생성 결과):

* `red_teaming/generated_tasks/<agent>/<YYYY-MM-DD>/redteam_tools.json`

이 파일은 LLM이 생성하는 것이 아니라,
기존 도메인의 `attack_tools.json` / `normal_tools.json`에서 필요한 부분을 재구성해 만듭니다.

핵심 목표:

* MCP server는 **attack 서버** 사용
* `allowed_tools`는 딱 **8개만** 노출

  * baseline 5 + memory 1 + 공격 성공 도구 2

---

## 2.6 공격 Task 생성 (tasks_attack.jsonl)

레드티밍 공격 Task는 LLM이 생성합니다.

출력 위치:

* `red_teaming/generated_tasks/<agent>/<YYYY-MM-DD>/tasks_attack.jsonl`

요구사항:

* 사람처럼 자연스러운 요청(업무 맥락이 살아있는 문장)
* JSONL 스키마는 코드가 강제

  * 예: `id`, `user`는 필수
  * `technique_id` 같은 메타는 optional

---

## 2.7 실행 순서 (End-to-End)

### Step 0) (1회) 도메인 모사환경이 준비되어 있어야 함

* MCP 서버 코드 존재
* `system.txt` 존재
* 도메인 tools json 존재

### Step 1) Agent Profile 생성

* 입력: 도메인 id (예: `ecommerce_operations_agent`)
* 출력: `red_teaming/agent_profiles/<agent>/<date>/agent_profile.yaml`

### Step 2) Red Team Scenarios/Tasks 생성

* 입력:

  * Step 1의 `agent_profile.yaml`
  * `technique_db` CSV
* 출력:

  * `red_teaming/generated_tasks/<agent>/<date>/tasks_attack.jsonl`
  * `red_teaming/generated_tasks/<agent>/<date>/redteam_tools.json`

### Step 3) 러너 실행(attack 모드)

* config는 redteam용으로 별도
* tools path는 `red_teaming/generated_tasks/.../redteam_tools.json`를 가리킴
* tasks path는 `red_teaming/generated_tasks/.../tasks_attack.jsonl`를 가리킴

예:

```bash
python run/run_ecomerce.py --config "configs/redteam/ecommerce_operations_agent.yml" --mode attack
```

### Step 4) 로그 분리(선택)

레드티밍 로그를 분리하고 싶으면 config에서:

```yaml
logging:
  base_dir: red_teaming/run/logs
```

---

# 참고: 현재 MVP 수치 요약(고정 가정)

* **도메인 수**: 5개
* **Task 수**: 도메인당 200개(정상 50 + 공격 150), 전체 1,000개
* **도구 수(도메인당)**

  * 정상 도구: baseline 5 + trusted RAG 1 = 6개
  * 공격 도구 풀: 공격 성공 도구 2 + IPI source 50 + untrusted RAG 1 = 53개
* **KB 문서 수(도메인당)**: Trusted 20 + Poisoned 20 = 40개
