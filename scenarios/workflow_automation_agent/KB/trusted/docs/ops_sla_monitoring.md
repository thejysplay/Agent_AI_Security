# doc_id: OPS-03
# 제목: SLA 및 모니터링 기준
# 키워드: SLA, latency, error_rate, alert
## SLA 기준
- 단일 실행 최대 30초
- 평균 5초 이하
- 실패율 5% 초과 시 Alert

## 모니터링 지표
- success_rate
- avg_latency
- retry_count
- queue_depth