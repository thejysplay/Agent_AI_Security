# doc_id: INTEG-01
# 제목: 외부 API 연동 가이드
# 키워드: API, timeout, rate limit
## 기본 설정
- Timeout 5초
- 429 응답 시 2초 후 재시도

## 장애 시
- 3회 실패 시 Incident 생성