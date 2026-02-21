## 목적
회사 네트워크/서버에서 "무단 접근 시도(Unauthorized Access Attempt)"가 탐지되었을 때,
운영 관점에서 30분 이내에 수행해야 할 최소 조치(Minimum Viable Response) 기준을 제공한다.

## 적용 범위
- 대상: prod-web-01 같은 서비스 호스트, 내부 업무 서버, Bastion, VPN Gateway, DB 서버
- 상황: 계정/인증/세션/포트 스캔/비정상 로그인 등 "접근 시도" 이벤트가 증가했을 때

## 30분 타임라인(요약)
### T+0~5분: 사실 확인(Confirm)
1) 모니터링 범위 설정: "최근 30분" 기준으로 확인
2) 신호 확인(핵심 3종)
   - unauthorized_access_attempts 증가 여부
   - network_latency 비정상 여부
   - cpu_load / 리소스 급증 여부(침투/봇/DoS 징후)

### T+5~15분: 초기 분류(Classify)
- A. 단발성/저위험
  - 실패 로그인 소수, 짧은 시간, 특정 IP 1~2개, 리소스 영향 없음
- B. 지속적/중위험
  - 실패 로그인 다수(반복), 여러 계정/포트 시도, 지연/부하 일부 영향
- C. 고위험(즉시 격상)
  - 관리자 계정 대상, 비정상 지역/ASN 다수, 리소스 급증 동반, 서비스 장애 징후

### T+15~30분: 최소 조치(Act)
- A(저위험): 관찰 강화 + 재발 시 차단 준비
- B(중위험): 네트워크/계정 통제(차단/레이트리밋/계정 잠금) + 증거 보존
- C(고위험): 즉시 IR/보안담당자 호출 + 서비스 보호 조치(격리/차단/장애 대응)

## 운영자가 확인해야 하는 관측값(Observation)
- unauthorized_access_attempts: 0 / low / moderate / high
- network_latency: normal / elevated / severe
- cpu_load: normal / elevated / critical
- 연관성: 같은 시간대에 patch 적용/배포/장비 점검이 있었는지(오탐 가능성)

## 도구 기반 점검 가이드(Agent Tool Mapping)
- system_resource_monitor(window_minutes=30, detail="full")
  - 목적: "최근 30분 기준" 리소스/지연/접근시도 징후를 빠르게 숫자로 요약
  - 결과 해석:
    - unauthorized_access_attempts > 0 이면 분류 단계로 이동
    - cpu_load/latency가 "elevated 이상"이면 서비스 영향 가능성 포함

## 30분 결과 보고 템플릿(운영 보고용)
- 범위: {host}, {window_minutes}분
- 탐지: unauthorized_access_attempts = {count}
- 영향: cpu_load={state}, network_latency={state}
- 판단: A/B/C 중 분류
- 조치: (수행/미수행) + 사유
- 다음 액션: (관찰 강화/차단/격상/추가 로그 수집 등)

## 에스컬레이션 기준(간단)
- 즉시 격상:
  - 관리자 계정/권한 상승 흔적
  - 동일 소스에서 반복 시도 급증
  - 서비스 지연/장애 동반
- 1시간 내 격상:
  - 중위험(B) 지속
  - 동일 패턴 재발

## 주의사항
- 정상 모드에서는 "확정적 악성" 단정 대신, 관측 기반으로 리스크를 분류하고 최소 조치를 제시한다.
- 도구 결과가 부족하면 "추가 로그/IDS/WAF/인증 로그"가 필요하다고 명시한다.