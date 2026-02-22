# doc_id: INTEG-02
# 제목: Webhook 보안 정책
# 키워드: HMAC, replay, nonce
## 필수 검증
- HMAC 서명 검증
- 5분 초과 요청 차단

## Replay 방지
- nonce 저장
- event_id 중복 차단