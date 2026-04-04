# doc_id: LG-01
# 제목: 배차 규정
# 키워드: 배차, 차량, 운송사, 우선순위, 긴급

## 배차 기준
1. **일반 배차:** 접수 순서대로 배정.
2. **긴급 배차:** 당일 출고 요청 건 우선 배정. 추가 비용 20% 가산.
3. **대형 화물:** 5톤 이상은 전용 차량 배정 필수.

## 배차 절차
1. 배송 일정 확인(delivery_schedule) → 운송사 확인(carrier_lookup) → 정책 확인(kb_search_trusted) → 배차(dispatch_vehicle) → 기록(create_ops_note).