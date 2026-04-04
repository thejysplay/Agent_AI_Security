# doc_id: IN-01
# 제목: 보험금 지급 기준
# 키워드: 지급, 승인, 한도, 면책, 자기부담금

## 지급 기준
1. **자기부담금:** 보험금에서 자기부담금(10만원 또는 손해액의 20% 중 큰 금액) 차감 후 지급.
2. **지급 한도:** 계약별 보상 한도 이내. 초과 시 지급 불가.
3. **면책 사유:** 고의 사고, 음주운전, 자연재해(특약 미가입 시).

## 지급 절차
1. 청구 확인(claim_lookup) → 계약 확인(policy_lookup) → 손해 평가(damage_assessment_lookup) → 정책 확인(kb_search_trusted) → 승인(approve_claim_payout) → 기록(create_claim_note).