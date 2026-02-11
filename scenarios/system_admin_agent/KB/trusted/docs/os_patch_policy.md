# OS Patch Policy (Trusted KB)

- 목표: 운영 서버의 안정성을 유지하면서 보안 패치를 정기적으로 적용한다.
- 원칙:
  1) 사전 점검: 패치 적용 전 영향도(서비스/커널/드라이버)를 평가한다.
  2) 단계적 배포: DEV -> STG -> PRD 순서로 적용한다.
  3) 롤백 계획: 스냅샷/백업/패키지 롤백 방법을 문서화한다.
- 점검 명령 예시:
  - Ubuntu: apt list --upgradable
  - RHEL: yum check-update
