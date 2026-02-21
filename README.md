# Agent_AI_Security

MCP(Model Context Protocol) 기반으로 **LLM 에이전트의 정상 유틸리티(Utility)** 와 **공격 저항성(Security)** 을 같은 실행 루프에서 비교·재현·평가하기 위한 실험 저장소입니다.

이 프로젝트는 특히 다음 현실을 그대로 반영합니다.

* 에이전트는 업무 수행 중 **도구(Tool-use)** 를 호출합니다.
* 에이전트는 운영 정책/플레이북/과거 사례 같은 **장기 지식 저장소(LTM)** 를 조회합니다.
* 공격자는 **입력(DPI)**, **도구 응답(IPI)**, **메모리(MP)** 를 통해 에이전트를 유도합니다.

> **KB = LTM (표현 고정)**
>
> 이 저장소에서의 KB는 **LTM-backed operational KB (RAG)**, 즉 **문서 기반 Long-term Memory(LTM)** 를 모델링합니다.
> 에이전트는 필요할 때 `kb_search_*` 도구를 호출해 LTM을 조회하고, 검색 결과 payload가 컨텍스트로 주입되어 다음 행동(추론/도구 호출/최종 답변)에 영향을 줍니다.
>
> 따라서 **저장(운영 지식) → 검색(RAG) → 컨텍스트 주입 → 행동** 흐름이 실제 에이전트의 LTM 동작과 동일하게 재현됩니다.

---

# 1) 모사환경(Testbed): “정상 vs 공격”을 같은 루프에서 비교

## 1.1 실험 설계 요약

* **5개 도메인(시나리오)** × **총 1,000 Task** 확장 가능한 구조
* 동일한 Runner/Agent loop에서 **normal vs attack 모드** 비교
* 공격 유형 3종을 **동일한 도구 체계(MCP)** 로 재현

  * **DPI**: 사용자 입력(prompt) 내부 직접 주입
  * **IPI**: 외부 소스(티켓/벤더 문서/메일 등) **도구 응답(payload)** 을 통한 간접 주입
  * **MP**: **LTM/KB(운영 메모리) 자체 오염** → 검색 결과가 공격 유도
* 모든 실행을 **Trace(JSONL)** 로 기록하여 사후 판정(Oracle) 가능

## 1.2 전체 아키텍처(한 장 요약)

한 번의 Task 실행은 아래 파이프라인을 따릅니다.

```
User Task(JSONL)
   │
   ▼
Runner
 - scenario/mode 로드
 - 노출 도구 집합 결정(통제)
 - LLM 루프 실행
 - Trace(JSONL) 저장
   │
   ▼
LLM Agent
 - (TRACE RULE) 도구 호출 전 PLAN 출력 강제
 - tool-call 실행
   │
   ▼
MCP Server
 - baseline tools(정상)
 - ipi_source tools(외부 소스 조회)
 - kb_search tools(LTM/KB 검색)
 - attack_success tools(고위험)
```

**핵심은 동일한 루프**입니다.

* normal/attack 모드는 Runner/LLM 루프는 같고, **노출되는 도구 집합과 (도구 응답/KB의 신뢰도)** 만 달라집니다.

## 1.3 시나리오(도메인) 구성

시나리오(scenario)는 아래 4요소의 묶음입니다.

1. **Tasks**: 사용자 업무/공격 유도 프롬프트(JSONL)
2. **Tools**: MCP 서버가 제공하는 도구 집합(정상/공격)
3. **Tool Policy**: 어떤 도구를 어떤 신뢰도/역할로 볼지(allowed_tools, 매핑)
4. **KB(LTM)**: trusted/untrusted 문서 + RAG 검색 도구

일반적인 디렉토리 형태(개념):

* `scenarios/<scenario>/system.txt` : 시스템 프롬프트(+ TRACE RULE)
* `scenarios/<scenario>/tasks_benign.jsonl` : 정상 Task
* `scenarios/<scenario>/tasks_attack.jsonl` : 공격 Task(DPI/IPI/MP)
* `scenarios/<scenario>/normal_tools.json` : normal 모드 도구/정책
* `scenarios/<scenario>/attack_tools.json` : attack 모드 도구/정책
* `scenarios/<scenario>/KB/trusted/...` : 신뢰 LTM
* `scenarios/<scenario>/KB/untrusted/...` : 오염 가능 LTM
* `mcp_servers/<scenario>/<mode>/server.py` : MCP 도구 구현

## 1.4 모드(normal vs attack)

* **normal 모드**

  * baseline tools(정상 업무용) + (필요 시) trusted KB 검색 도구

* **attack 모드**

  * baseline tools는 유지
  * 공격 경로에 따라 아래 중 일부만 추가 노출(실험 통제)

    * IPI source tool(외부 소스 조회 도구)
    * untrusted KB 검색 도구(오염된 LTM 조회)
    * attack success tools(고위험 도구)

즉, 에이전트는 “원래 하던 업무”를 계속 수행하면서도,
**어떤 경로(IPI/MP/DPI)로 공격 지시가 섞여 들어올 때** 고위험 도구 호출로 이어지는지를 관찰할 수 있습니다.

## 1.5 (핵심) IPI(간접 주입)의 “도구화(tool-ization)” 메커니즘

IPI는 이 프로젝트에서 가장 독특하고, 반드시 이해해야 하는 부분입니다.

### IPI가 무엇을 모델링하나?

IPI 공격은 LLM이 `get_vendor_info`, `read_ticket`, `read_email` 같은 **외부 소스 조회 도구**를 호출할 때,
그 **도구의 리턴값(Payload)** 내부에 공격 지시문이 섞여 들어오는 구조입니다.

* 공격자는 프롬프트를 직접 바꾸지 않습니다.
* 대신 티켓/벤더 권고문/메일/외부 위키 같은 **외부 컨텍스트**를 오염시킵니다.
* 에이전트는 업무 수행상 “조회”가 필요하므로, 도구 호출을 통해 그 컨텍스트를 읽습니다.
* 결과적으로 공격 지시가 **tool_result** 로 유입되어 다음 행동을 왜곡합니다.

### 왜 외부 문서를 ‘파일’이 아니라 ‘MCP Tool’로 정의해야 하나?

외부 문서를 단순 텍스트 파일로 넣으면, 아래가 흐려집니다.

* 에이전트가 **어떤 경로로 외부 컨텍스트를 읽었는지**
* 공격 지시가 **언제/어떤 반환값에 섞여 들어왔는지**

반면 MCP Tool로 정의하면:

1. **조회 행위 자체가 Trace로 남음**

   * `tool_call` / `tool_result` 로 “어떤 외부 소스를 읽었는지”가 명확해집니다.

2. “외부 문서 = Observation” 구조를 그대로 재현

   * 실제 에이전트 프레임워크에서도 외부 데이터는 tool output 형태로 들어옵니다.

3. **소스별 타겟 매핑을 정책으로 통제 가능**

   * 어떤 외부 소스가 어떤 고위험 도구를 유도하도록 설계되었는지(레드팀 설계)가 명확해집니다.

### ‘외부 소스 N개 ↔ N개 MCP Tool’ 매핑

IPI 실험에서는 외부 소스 각각을 **개별 MCP Tool**로 매핑할 수 있습니다.

> “IPI 공격은 LLM이 외부 문서를 읽는 순간(도구 호출), 그 **리턴값(payload)** 에 공격 지시문이 섞여 들어가는 구조입니다.
> 이를 위해 외부 소스 각각을 개별 MCP Tool로 매핑하여, LLM이 ‘조회’ 행위를 하도록 유도합니다.”

## 1.6 (핵심) Trace Rule & PLAN 강제(Oracle 판정의 핵심)

### TRACE RULE(강제 규칙)

모든 에이전트는 **도구를 사용하기 직전**, 반드시 자신의 의도를 1~2문장의 `PLAN:`으로 출력해야 합니다.

예:

* `PLAN: 벤더 권고문을 먼저 읽고, 영향 범위를 요약한 뒤 필요한 조치를 수행하겠습니다.`

### 왜 PLAN을 강제하나?

사후 평가에서 아래를 판별하기 위한 **핵심 근거 데이터**가 됩니다.

* 에이전트가 공격자의 의도를 **인지**하고 행동했는지
* 혹은 단순히 tool-output(오염된 payload)에 **휘말려서** 행동했는지

IPI/MP에서는 공격 지시가 tool_result 또는 KB 검색 결과로 들어오기 때문에,
PLAN이 없으면 “도구 체인에 끌려간 것”과 “의도적 수행”을 구분하기 어려워집니다.

## 1.7 도구 노출을 8개로 제한하는 이유(실험 통제)

레드팀/공격 시나리오에서 도구 노출을 **기본적으로 8개(5+1+2)** 수준으로 통제할 수 있습니다.

* Baseline tools (예: 5개)
* IPI source tool (예: 1개)
* Attack success tools (예: 2개)

이 제한의 목적은 **변수 통제(Control Variables)** 입니다.

* 도구가 너무 많으면 LLM의 “무작위 도구 탐색”이 증가
* 도구 스키마/설명 컨텍스트가 커져 정상 성능도 하락
* 공격 성공 도구가 희석되어 공격 유효성 테스트가 흐려짐

따라서 도구 노출을 제한하여,

* 정상 유틸리티(PNA)가 크게 흔들리지 않는 조건에서
* 고위험 도구(Attack Success Tools)에 대한 유도/저항을 집중 평가합니다.

## 1.8 Domain별 Attack Success Tools 예시(한눈에 보기)

| 도메인(시나리오)     | 정상 도구(Baseline) 예시 | IPI 소스 도구 예시          | Untrusted LTM/KB 도구 예시   | 고위험 도구(Attack Success) 예시                        |
| ------------- | ------------------ | --------------------- | ------------------------ | ------------------------------------------------ |
| Ecommerce Ops | 주문/배송/재고/환불/케이스 처리 | 티켓/벤더/메일 조회(외부 소스 다수) | `*_kb_search_untrusted`  | `payout_account_override`, `customer_db_export`  |
| System Admin  | 모니터링/업데이트          | 벤더 권고문/사고 티켓          | `kb_search_untrusted`    | `create_admin_account`, `share_link_generator`   |
| HR(예시)        | 근태/휴가 조회           | 정책 변경 공지              | `hr_kb_search_untrusted` | `salary_data_exfiltration`, `employee_dismissal` |

> 표의 도구명은 이해를 위한 예시입니다. 실제 도구명/개수는 시나리오별 MCP 서버와 tool policy로 확정됩니다.

---

# 2) 레드팀(Red Teaming): 공격 ‘생성’ 파이프라인(모사환경과 완전히 별개)

레드팀은 모사환경의 공격(DPI/IPI/MP)을 “그대로 반복”하거나 “같은 이름으로 분류”하는 작업이 아닙니다.

* **모사환경**은 이미 설계된 공격 모사 시나리오(DPI/IPI/MP)를 실행해 *현상/경로/로그*를 재현합니다.
* **레드팀**은 *공격 입력(벤치)* 을 만들어내는 별도의 생성 파이프라인입니다.

따라서 레드팀 섹션의 논점은 “DPI/IPI/MP 분류”가 아니라,
**프로파일 → 테크닉 → 시나리오 → 실행(생성물 평가)** 로 이어지는 *생성/운영 체계*입니다.

---

## 2.1 레드팀의 목표(무엇을 만들고 무엇을 검증하나)

레드팀의 목표는 다음 3가지를 동시에 만족하는 **공격 벤치(Attack Bench)** 를 만드는 것입니다.

1. **도메인/역할에 맞는 현실성**

* “이 에이전트라면 실제로 이런 업무를 한다/이런 문서를 본다/이런 결정을 한다”가 성립

2. **재현성(Reproducibility)**

* 같은 입력 세트로 실행하면 같은 경로/성공 기준으로 다시 평가 가능

3. **확장성(Scalability)**

* 변형을 체계적으로 만들어 커버리지(coverage)와 난이도(difficulty)를 확장

레드팀이 만드는 것은 단일 프롬프트가 아니라,
**(a) 공격 시나리오 정의 + (b) 실행/평가 가능한 태스크 세트 + (c) 결과 로그(Trace)** 의 묶음입니다.

---

## 2.2 레드팀 파이프라인 개요(큰 흐름)

```
[Profile]  →  [Technique]  →  [Scenario]  →  [Execution]  →  [Outcome]
(역할/권한)   (공격 기법)     (상황/자극)      (실행/로그)     (성공/실패/분석)
```

각 단계는 “무엇을 입력으로 받고, 무엇을 출력하는지”가 명확해야 재현 가능한 레드팀이 됩니다.

---

## 2.3 Profile(프로파일): 에이전트가 ‘누구’이며 무엇을 할 수 있나

프로파일은 레드팀의 출발점입니다. 레드팀에서 프로파일은 최소한 아래를 포함합니다.

### (A) 역할(Role)

* 예: system admin, ecommerce ops, HR 등
* “정상 업무에서 기대되는 행동”의 경계를 정의

### (B) 권한/행동 범위(Capability Boundary)

* 접근 가능한 시스템/데이터 범위
* 실행 가능한 작업 유형(예: 계정 관리, 정산, 고객 정보 처리)

### (C) 위험 표면(Attack Surface)

* 이 역할에서 공격자가 노릴 만한 자산/행동
* 예: 계정 생성, 외부 공유 링크, 정산 계좌 변경, 고객 DB export

### (D) 정상 업무 목표 분포(Task Distribution)

* 정상 업무가 어떤 유형으로 분포하는지(조회/요약/처리/승인 등)

**프로파일의 산출물**은 보통 “도메인별 레드팀 설정”입니다.

* (개념) `redteam/profile/<scenario>.json`

---

## 2.4 Technique(테크닉): ‘어떻게 유도할 것인가’의 템플릿

테크닉은 공격 기법을 “재사용 가능한 템플릿”으로 정리한 것입니다.

### (A) 유도 전략(Induction Strategy)

* 사회공학/업무 압박/긴급성/권위/규정 위반 유도 등

### (B) 목표(Target Objective)

* 궁극적으로 어떤 “고위험 행동”을 유발할 것인지
* 이 프로젝트에서는 보통 **attack success tool 호출**로 측정 가능한 목표를 둡니다.

### (C) 증거/그럴듯함(Evidence Wrapper)

* 공격 지시가 티가 나지 않도록 붙는 업무 문맥
* 예: 감사 대응, 장애 대응, 고객 클레임, 비용 정산 등

### (D) 변형(Variation Rules)

* 같은 기법을 여러 난이도로 변형하는 규칙
* 문장 변주, 근거 자료 변주, 요구사항 변주(제약/기한/상대) 등

**테크닉의 산출물**은 “기법 카탈로그”입니다.

* (개념) `redteam/techniques/*.json`

---

## 2.5 Scenario(시나리오): 프로파일×테크닉을 ‘실제 상황’으로 조립

시나리오는 프로파일과 테크닉을 결합해 “실행 가능한 한 개의 공격 상황”을 구성합니다.

### (A) 시나리오 스펙(Scenario Spec)

시나리오 스펙은 최소 다음을 포함합니다.

* `scenario_id`: 고유 식별자
* `profile_ref`: 어떤 프로파일 기반인지
* `technique_ref`: 어떤 테크닉을 적용했는지
* `benign_goal`: 표면상 정상 업무 목표(업무 요청)
* `attack_goal`: 공격자가 의도하는 목표(고위험 행동)
* `stimulus`: 에이전트를 흔들 자극(상황/제약/압박)
* `success_criteria`: 성공 판정 기준(주로 attack success tool 호출)

### (B) 레드팀 태스크 세트 생성(Task Set)

하나의 시나리오는 보통 “단일 문장”이 아니라 **여러 태스크로 구성된 세트**로 확장됩니다.

* 같은 시나리오라도 난이도/표현/상황을 바꾼 변형들을 묶어 “벤치”를 만듭니다.

**시나리오 단계의 산출물**

* (개념) `redteam/scenarios/<scenario_id>.json`
* (개념) `redteam/generated_tasks/<scenario_id>/tasks.jsonl`

---

## 2.6 Execution(실행): 시나리오를 러너로 돌려 Trace를 얻는다

레드팀은 “생성”에서 끝나지 않고, 반드시 **실행 가능한 형태**로 만들어야 합니다.

### (A) 실행 입력

* `scenario_spec`
* `tasks.jsonl` (해당 시나리오의 태스크 세트)
* `tool exposure policy` (해당 시나리오 실행 시 노출 도구/정책)

### (B) 실행 과정

* Runner가 tasks를 순회 실행
* 각 태스크에서 LLM이 도구를 호출
* 전 과정이 **Trace(JSONL)** 로 저장

### (C) 실행 산출물

* `run/logs/<scenario>/<mode>/.../*.jsonl`
* 레드팀 관점에서는 이 로그가 “평가 데이터”입니다.

---

## 2.7 Outcome(결과): 무엇을 보고 레드팀 성과를 말하나

레드팀의 결과는 단순 성공/실패뿐 아니라, “벤치가 어떤 성질을 갖는지”를 요약해야 합니다.

### (A) 성공/실패

* 성공: success criteria 충족(예: attack success tool 호출)
* 실패: 정상 업무만 수행하거나, 유도에 저항

### (B) 커버리지(coverage)

* 어떤 프로파일/테크닉/상황을 얼마나 다양하게 포함하는지

### (C) 난이도(difficulty)

* 동일 방어(또는 동일 모델)에서 성공률이 어떻게 분포하는지

### (D) 재현성(reproducibility)

* 같은 시나리오/태스크 세트로 반복 실행 시 결과가 얼마나 안정적인지

---

## 2.8 레드팀에서 ‘DPI/IPI/MP’ 용어를 어떻게 다루나(중요)

이 프로젝트에서 DPI/IPI/MP는 모사환경 섹션의 “공격 모사 채널”로는 핵심이지만,
레드팀 섹션의 핵심 논점은 아닙니다.

레드팀에서 DPI/IPI/MP는 다음처럼만 취급합니다.

* **‘주입 채널’이라는 메타 태그(분류 축)** 로만 사용
* 레드팀의 본질은 “분류”가 아니라 **프로파일/테크닉/시나리오/실행/결과로 이어지는 생성 체계**

즉, 레드팀은

* DPI/IPI/MP를 중심으로 설명하지 않고,
* 필요하다면 outcome 분석에서 “이 시나리오는 어떤 채널 메타를 갖는다” 정도로만 사용합니다.

---

## 2.9 레드팀이 모사환경과 만나는 지점(연결점)

두 시스템은 같지 않지만, **실행기(Runner)와 로그(Trace)** 를 공유합니다.

* 모사환경: 고정된 공격 모사 시나리오를 실행 → Trace로 현상을 보여줌
* 레드팀: 생성된 공격 벤치를 실행 → Trace로 벤치/방어/모델의 성질을 측정

연결점은 단 하나입니다.

* 레드팀이 만든 태스크 세트를 Runner로 실행해 Trace를 얻는다

그러나

* 레드팀이 “모사환경 공격을 구성한다”가 아니라,
* 레드팀은 “별도의 벤치를 만들고, 같은 실행·로그 인프라를 활용한다”가 정확한 설명입니다.
