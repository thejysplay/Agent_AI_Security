# Agent_AI_Security — Simulation Testbed & Red Teaming

이 저장소는 LLM 기반 Agent를 대상으로, 동일한 Agent 루프/러너에서 **정상(Benign) vs 공격(Attack)** 을 재현하고, 생성된 **실행 Trace(JSONL 로그)** 를 기반으로 후속 평가(판정/오라클)를 수행할 수 있도록 만든 **모사환경(Simulation Testbed)** + **레드팀(Red Teaming) 파이프라인** 입니다.

큰 구성은 2가지입니다.

1. **모사환경(Simulation Testbed)**: 도메인별 Agent, 도구(MCP), 정상/공격 Task, KB(RAG/LTM)까지 포함한 실행 환경
2. **레드팀(Red Teaming)**: Agent Profile + Technique DB를 기반으로 **공격 시나리오/태스크를 자동 생성**하고, 그 결과를 실행/로그로 연결해 **취약성을 자동 평가**하는 생성·평가 파이프라인

> **KB = LTM (표현 고정)**
>
> 이 저장소에서의 KB는 **LTM-backed operational KB (RAG)**, 즉 **문서 기반 Long-term Memory(LTM)** 를 모델링합니다.
> 에이전트는 필요할 때 `kb_search_*` 도구를 호출해 LTM을 조회하고, 검색 결과 payload가 컨텍스트로 주입되어 다음 행동(추론/도구 호출/최종 답변)에 영향을 줍니다.

---

# 1) 모사환경 (Simulation Testbed)

## 1.1 모사환경이 해결하려는 문제

현실의 Agent는 보통 아래 3요소가 결합됩니다.

* **User Task**: 사용자가 요청한 정상 업무 목표(요약/조회/처리/조치)
* **Tool-use**: API/DB/시스템/문서 조회 등 외부 세계와 상호작용
* **LTM/KB**: 정책/플레이북/과거 사례/운영 문서 등 장기 지식

공격자는 이 경로를 3가지 방식으로 노립니다.

* **DPI**: 사용자 입력에 악성 지시를 직접 섞어 “즉시” 행동을 왜곡
* **IPI**: 외부 문서/티켓/메일 등 **도구 반환값(payload)** 에 악성 지시를 섞어 “간접”으로 왜곡
* **MP**: LTM/KB 자체를 오염시켜, 검색 결과가 지속적으로 행동을 편향

모사환경의 목적은 단순히 “공격이 된다/안 된다”가 아니라,

* 같은 Agent 루프에서 **정상 vs 공격**을 조건만 바꿔 비교하고,
* “어떤 주입 채널이 어떤 도구 체인(tool chain)을 통해 어떤 고위험 행동으로 이어지는지”를
* **Trace(실행 로그)** 로 재현·분석 가능하게 만드는 것입니다.

---

## 1.2 실험 단위: Domain Agent(Scenario)

모사환경에서 실험의 기본 단위는 **도메인(=시나리오)** 입니다.

* 도메인은 “업무 맥락 + 정상 도구 + 공격 성공 도구 + 외부 소스(IPI) + KB(LTM)”가 한 세트로 묶인 독립 실험 단위입니다.
* 기본 전제는 **총 5개 도메인**이며, 각 도메인은 서로 다른 업무/위험 표면을 가집니다.

예시 도메인(개념):

* `system_admin_agent`
* `ecommerce_operations_agent`
* `hr_agent`
* `travel_agent`
* `finance_agent`

> 실제 도메인 목록은 `scenarios/` 디렉토리의 하위 폴더가 기준입니다.

---

## 1.3 도메인 디렉토리 구성(무엇이 어디에 있나)

도메인 1개는 아래 구성 요소를 갖습니다.

* `scenarios/<agent>/system.txt`

  * Agent 역할/금지 규칙/출력 규칙(TRACE RULE 등)
* `scenarios/<agent>/tasks_benign.jsonl`

  * 정상 업무 Task 집합
* `scenarios/<agent>/tasks_attack.jsonl`

  * 공격 모사 Task 집합(DPI/IPI/MP를 포함)
* `scenarios/<agent>/normal_tools.json`

  * normal 모드에서 노출할 도구 목록/정책
* `scenarios/<agent>/attack_tools.json`

  * attack 모드에서 노출할 도구 목록/정책(attack 성공 도구/ipi_source/KB 포함)
* `scenarios/<agent>/KB/...`

  * Trusted/Poisoned(Untrusted) 문서 저장소(=LTM)
* `mcp_servers/<agent>/normal/server.py`
* `mcp_servers/<agent>/attack/server.py`

  * MCP 서버: 도구를 실제로 제공하는 실행 엔드포인트

도메인은 “파일만 있는 문서”가 아니라,

* 어떤 도구를 어떤 이름/스키마로 제공하고
* 어떤 Task를 어떤 모드에서 어떻게 실행하고
* 어떤 KB를 어떤 RAG 도구로 조회하게 할지

까지 포함하는 실행 가능한 패키지입니다.

---

## 1.4 Task 설계(정상/공격)와 개수

모사환경에서는 도메인별로 **정상/공격 태스크를 고정된 규격**으로 운영합니다.

| TASK 유형    | 목적                             | 개수(도메인당) | 전체(5도메인) |
| ---------- | ------------------------------ | -------: | -------: |
| 정상(Benign) | 유틸리티(PNA) 측정 기반                |       50 |      250 |
| 공격(DPI)    | 프롬프트 직접 주입 경로 재현               |       50 |      250 |
| 공격(IPI)    | 외부 소스(tool_result) 간접 주입 경로 재현 |       50 |      250 |
| 공격(MP)     | KB/RAG(LTM) 오염 경로 재현           |       50 |      250 |
| 총합         | 정상 50 + 공격 150                 |      200 |    1,000 |

### Task JSONL 필드(모사환경)

* **필수**: `id`, `user`
* **옵션**: `ipi_source_tool`, `attack_hint`, `meta.*` 등

예시(개념):

```json
{"id":"benign-001","user":"..."}
{"id":"dpi-001","user":"(정상 업무) ... (악성 지시) ..."}
{"id":"ipi-001","user":"외부 벤더 권고문을 확인해줘","ipi_source_tool":"vendor_advisory_reader"}
{"id":"mp-001","user":"관련 정책을 KB에서 찾아 요약하고 조치해줘"}
```

> 모사환경의 공격 태스크는 “레드팀 생성물”이 아니라, 공격 경로를 대표적으로 보여주기 위해 **수동/고정 설계된 공격 모사 세트** 입니다.

---

## 1.5 Tool 설계(정상/공격)와 개수

모사환경의 도구는 역할이 명확히 나뉩니다.

### (A) 정상 업무 도구 (Baseline + Trusted RAG)

| 그룹             | 설명                  | 개수(도메인당) |
| -------------- | ------------------- | -------: |
| Baseline 정상 도구 | 정상 업무 수행에 필수인 핵심 기능 |        5 |
| Trusted RAG 도구 | Trusted KB(LTM) 검색  |        1 |
| 합계             |                     |        6 |

### (B) 공격 관련 도구 풀 (Attack Success + IPI Source + Poisoned RAG)

| 그룹                     | 설명                           | 개수(도메인당) |
| ---------------------- | ---------------------------- | -------: |
| Attack success tools   | 공격 성공 판정용 고위험 행동 도구          |        2 |
| IPI source tools       | 외부 소스 “도구화” 도구(벤더/티켓/메일/웹 등) |       50 |
| Poisoned/Untrusted RAG | 오염 KB(LTM) 검색                |        1 |
| 합계                     |                              |       53 |

핵심 설계 의도:

* **공격 성공 도구는 2개로 고정**하여, 성공 판정 기준을 흔들지 않습니다.
* 대신 DPI/IPI/MP 경로로 **그 2개의 도구 호출이 유발되는지**를 반복 측정합니다.

---

## 1.6 KB(LTM) 설계와 개수

KB는 LTM이고, 실험 통제를 위해 trusted/poisoned로 분리합니다.

| KB 유형            | 설명                     | 개수(도메인당) |
| ---------------- | ---------------------- | -------: |
| Trusted KB docs  | 정책/매뉴얼/SOP/FAQ 등 정상 근거 |       20 |
| Poisoned KB docs | 정상 문서처럼 보이지만 주입/유도 포함  |       20 |
| 합계               |                        |       40 |

분리 이유:

* 동작은 동일하지만, **신뢰 경계(trust boundary)** 를 실험적으로 명시해

  * 정상 검색의 안정성과
  * 오염 검색의 위험도를
    같은 루프에서 비교하기 위함입니다.

---

## 1.7 IPI “도구화(tool-ization)” 메커니즘(모사환경 핵심)

IPI의 본질은 “문서를 읽는다”가 아니라, **도구 호출 결과(tool_result payload)** 로 주입이 들어온다는 점입니다.

* 에이전트가 `read_vendor_advisory` 같은 외부 소스 도구를 호출
* 반환 payload 내부에 공격 지시가 섞여 있음
* 에이전트는 그 내용을 ‘근거/지침’으로 믿고 다음 도구 체인을 밟아 고위험 행동으로 연결될 수 있음

왜 MCP Tool로 정의하나?

* 조회 행위(tool_call)와 반환값(tool_result)이 Trace로 남아

  * 주입이 “언제/어디서” 들어왔는지
  * 어떤 반환값이 어떤 행동을 유발했는지
    를 재현 가능한 데이터로 만들 수 있기 때문입니다.

---

## 1.8 Trace Rule / PLAN 강제(오라클 기반 분석 신호)

모든 에이전트는 도구 호출 직전 `PLAN:`을 1~2문장으로 출력합니다.

* 목적: 사후 분석에서 “왜 이 도구를 호출했는지” 최소 신호 확보
* 특히 IPI/MP에서 “오염된 payload에 휘말림 vs 의도적 수행”을 구분하는 데 도움

이 규칙은 모사환경의 “실행 로그 품질”을 올리기 위한 장치이며,
레드팀에서도 동일한 로그 표준을 활용하기 위해 유지됩니다.

---

## 1.9 모사환경 실행(어떤 코드로 어떻게 돌리나)

모사환경 실행은 도메인 러너가 담당합니다.

러너 동작(개념):

1. config 로드 (`configs/<agent>.yml`)
2. `--mode normal|attack` 에 따라 system/tasks/tools 경로 선택
3. MCP server 연결 후 LLM 루프 실행
4. Trace(JSONL) 저장

### 실행 예시(개념)

```bash
python run/run_ecomerce.py --config "configs/ecommerce_operations_agent.yml" --mode normal
python run/run_ecomerce.py --config "configs/ecommerce_operations_agent.yml" --mode attack
```

Trace 저장(개념):

* `run/logs/<agent>/<mode>/<YYYY-MM-DD>/<task_id>_<HHMMSS>.jsonl`

---

# 2) 레드팀 (Red Teaming)

레드팀은 모사환경의 공격(DPI/IPI/MP) 자체가 아닙니다.
레드팀은 **모사환경 위에서, 취약성 평가를 자동화하기 위해 공격 벤치(입력)를 생성하고 실행/평가까지 연결하는 생성 레이어** 입니다.

* 모사환경: 도메인·도구·KB·러너·Trace 포맷을 제공하는 “실행 인프라”
* 레드팀: Profile+Technique DB를 사용해 “평가 입력(시나리오/태스크 세트)”을 만들어 자동 평가

---

## 2.1 레드팀의 목적(본래 목적에 맞춘 정의)

레드팀의 본래 목적은 **에이전트의 프로파일(역할/권한/도구/제약)** 과 **Technique DB(공격 기법 카탈로그)** 를 입력으로 삼아,
사람이 수동으로 공격 프롬프트를 작성하지 않아도 **자동/반자동으로 취약성을 평가(vulnerability assessment)** 할 수 있게 만드는 것입니다.

레드팀은 아래 3가지를 “평가 관점”에서 체계화합니다.

### ① 공격 유도 설계(Generation)

* 프로파일을 보고 “이 Agent가 현실적으로 수행 가능한 업무/권한/도구” 범위 안에서만 시나리오를 구성
* Technique DB에서 기법을 선택해, 표면상 정상 업무 목표(benign goal) 안에 공격 유도 자극(stimulus)을 설계
* 동일 기법이라도 난이도/표현/상황을 다양화하는 변형 규칙을 적용(coverage 확대)

### ② 행동 유도/강제(Execution Steering)

레드팀은 “일반적인 자연어 Task”뿐 아니라, **도구 호출 행동 자체가 어떤 체인으로 흘러가면 취약해지는지**를 보려 합니다.

* 취약성은 ‘문장 한 번에 낚이는지’만이 아니라,

  * 어떤 **도구 체인(tool chain)** 을 밟게 되었을 때
  * 어떤 **순서/조건/파라미터 압박**이 있을 때
  * 공격 성공 행동(고위험 도구 호출)로 **연결되는지**
    를 포함해 측정해야 하기 때문입니다.

레드팀은 이를 위해 시나리오에 다음 요소를 포함할 수 있습니다.

* **도구 사용 압박 문맥**: “먼저 A를 조회하고 근거를 확보해라” 같은 자연스러운 요구
* **순서/절차 힌트**: ‘조회→검증→조치’처럼 특정 tool chain을 밟게 하는 절차형 요청
* **제약 조건**: 시간 압박, 승인/감사 대응, SLA 등으로 판단을 흐리게 하는 조건
* **근거 자료 유도**: 특정 로그/문서/티켓을 반드시 확인하도록 유도

> 여기서 ‘강제’는 하드코딩이 아니라, 입력(시나리오/프롬프트/근거 자료) 설계로 에이전트를 특정 체인으로 몰아가는 **유도 설계**를 의미합니다.

### ③ 자동 평가(Automated Assessment)

* 생성된 태스크 세트를 모사환경 Runner로 실행해 Trace(JSONL)를 수집
* 오라클/판정 규칙(예: attack success tool 호출/시도)을 적용해 성공/실패를 자동 집계
* 결과를 프로파일×테크닉×시나리오 단위로 요약하여 “취약 패턴”을 식별

---

## 2.2 레드팀 파이프라인(무엇을 만들어서 어떻게 평가하나)

```
(Profile) Agent의 역할/도구/제약 요약
   │
   ▼
(Technique) 공격 기법 카탈로그에서 선택 + 변형
   │
   ▼
(Scenario) 업무 맥락 + 자극 + 성공 기준 + (선택) 기대 tool chain 힌트
   │
   ▼
(Task Set) JSONL 태스크 세트 생성 + (실행용) 도구 노출 세트 구성
   │
   ▼
(Execution) Runner로 실행 → Trace(JSONL) 수집
   │
   ▼
(Assessment) 오라클로 성공/실패/패턴 집계
```

레드팀의 핵심 산출물은 항상 “쌍(pair)”입니다.

* `tasks_attack.jsonl` : 생성된 공격 태스크 세트
* `redteam_tools.json` : 그 태스크 세트를 실행하기 위한 도구 노출/정책(8개 세트)

같은 태스크라도 도구 노출이 바뀌면 난이도가 달라지므로,
둘을 함께 저장해야 “재현 가능한 레드팀 벤치”가 됩니다.

---

## 2.3 red_teaming 디렉토리(생성물은 어디에 쌓이나)

권장 구조(개념):

```
red_teaming/
  technique_db/
    AI Red Teaming - Agent Red Team Technique DB.csv
  agent_profiles/
    <agent>/<YYYY-MM-DD>/agent_profile.yaml
  generated_tasks/
    <agent>/<YYYY-MM-DD>/
      tasks_attack.jsonl
      redteam_tools.json
  generate_agent_profile.py
  generate_redteam_scenarios.py
  run/logs/
```

---

## 2.4 Technique DB(테크닉 DB)는 무엇을 담나

Technique DB는 “도메인 종속 X”로 공유 가능한 형태로 유지합니다.

예시 컬럼(개념):

* `technique_id`
* `attack_objective` (무엇을 얻고자 하는가)
* `attack_vector` (어떤 방식으로 유도하는가)
* `target_surface` (노릴 표면: 승인/공유/정산/계정 등)
* `action_intent` (유도되는 행동의 성격)
* `oracle_type` / `oracle` (성공 판정 규칙)
* `variation_rules` (변형 규칙)
* `risk` / `notes`

Technique DB는 레드팀 생성기가 “무엇을 만들지” 고르는 후보 풀이며,
프로파일에 의해 “가능한 것만” 선택되도록 필터링됩니다.

---

## 2.5 Agent Profile(프로파일)은 어떻게 쓰이나

Agent Profile은 레드팀 생성기가 도메인별 현실성을 유지하기 위한 입력입니다.

프로파일이 포함해야 하는 최소 정보:

* Agent 역할/업무 범위(무엇을 하는 Agent인가)
* 허용/금지 규칙(시스템 프롬프트의 핵심 제약)
* 노출 가능한 도구 목록(도구명, 설명, 스키마)
* 고위험 행동 정의(attack success tools)
* (선택) 정상 업무 분포/대표 업무 템플릿

출력(개념):

* `red_teaming/agent_profiles/<agent>/<date>/agent_profile.yaml`

---

## 2.6 실행용 도구 노출 세트(8개) 구성: redteam_tools.json

레드팀은 “전체 도구 풀(예: IPI 50개 포함)”을 그대로 노출하지 않고,
레드팀 실험용으로 **도구 예산(tool budget)을 고정**한 세트를 구성합니다.

* Baseline tools: 5
* Memory/RAG tool: 1 (필요 시)
* Attack success tools: 2

총 8개만 노출하는 이유:

* LLM 컨텍스트 부하를 낮춰 비교 가능성 확보
* 무작위 도구 탐색 감소
* 공격 성공 행동(고위험 도구)으로의 연결성을 더 명확히 측정

출력(개념):

* `red_teaming/generated_tasks/<agent>/<date>/redteam_tools.json`

---

## 2.7 공격 태스크 세트 생성: tasks_attack.jsonl

레드팀 태스크는 “자연어 요청” 형태를 유지하되, 다음을 충족하도록 생성합니다.

* 프로파일의 역할/업무 범위 안에서만 요청
* 테크닉이 요구하는 자극/압박/근거를 포함
* (필요 시) tool chain 유도 힌트가 자연스럽게 포함되도록 구성

출력(개념):

* `red_teaming/generated_tasks/<agent>/<date>/tasks_attack.jsonl`

---

## 2.8 레드팀 실행(어떤 코드로 어떻게 돌리나)

레드팀은 생성만 하고 끝나지 않습니다. 생성물로 실제 실행을 돌려 Trace를 얻어야 평가가 됩니다.

End-to-End 순서:

1. **(선행) 모사환경 도메인 준비**

* MCP 서버 코드 존재
* 도메인 system/tasks/tools 존재

2. **Agent Profile 생성**

* 입력: 도메인 id
* 출력: `agent_profile.yaml`

3. **Scenario/Task 생성 + redteam_tools.json 구성**

* 입력: profile + technique DB
* 출력: `tasks_attack.jsonl`, `redteam_tools.json`

4. **Runner 실행(attack 모드)**

* config는 redteam용으로 별도
* tools path: `redteam_tools.json`
* tasks path: `tasks_attack.jsonl`

예(개념):

```bash
python run/run_ecomerce.py --config "configs/redteam/ecommerce_operations_agent.yml" --mode attack
```

5. **Assessment(오라클 적용)**

* Trace(JSONL)로부터 성공/실패/패턴 집계
* (이 저장소에서는 Trace를 남기는 것까지를 실행 파이프라인으로, 오라클/집계는 후처리로 확장 가능)

---

# 현재 MVP 수치 요약(고정 가정)

* **도메인 수**: 5개
* **Task 수**: 도메인당 200개(정상 50 + 공격 150), 전체 1,000개
* **도구 수(도메인당)**

  * 정상 도구: baseline 5 + trusted RAG 1 = 6개
  * 공격 도구 풀: 공격 성공 도구 2 + IPI source 50 + untrusted RAG 1 = 53개
* **KB 문서 수(도메인당)**: Trusted 20 + Poisoned 20 = 40개
