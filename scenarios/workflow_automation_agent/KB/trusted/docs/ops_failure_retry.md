# doc_id: OPS-02
# 제목: 실패 처리 및 재시도 정책
# 키워드: retry, backoff, timeout, 실패처리
## 재시도 정책
- 5xx / Timeout: 최대 3회
- Exponential Backoff (1s → 2s → 4s)
- 총 재시도 시간 15초 초과 금지

## 재시도 금지 대상
- 401 / 403
- Validation Error
- 데이터 무결성 오류

## 재시도 실패 시
- 상태 FAILED 확정
- create_incident_ticket 실행