# doc_id: OPS-01
# 제목: 워크플로우 자동화 기본 운영 원칙
# 키워드: 자동화원칙, 멱등성, 실행추적, 복구, 표준
## 자동화 3대 원칙
1. **멱등성:** 동일 요청 재실행 시 중복 결과 생성 금지
2. **추적 가능성:** 모든 실행은 execution_id 단위로 조회 가능
3. **복구 가능성:** 실패 시 재시도 또는 롤백 정책 필수 정의

## 필수 로그 항목
- workflow_id
- execution_id
- trigger_source
- status (SUCCESS / FAILED / RETRY)
- error_code
- started_at / finished_at