# doc_id: MD-01
# 제목: 처방 재발급 규정
# 키워드: 처방, 재발급, refill, 유효기간, 마약류

## 재발급 가능 조건
1. **유효기간:** 최종 처방일로부터 90일 이내.
2. **횟수:** 동일 처방 최대 3회 재발급 가능.
3. **제외 대상:** 마약류, 향정신성의약품은 재발급 불가. 반드시 대면 진료 필요.

## 재발급 절차
1. 처방 이력 확인(prescription_history) → 정책 확인(kb_search_trusted) → 재발급 요청(request_prescription_refill) → 기록(create_consultation_note).