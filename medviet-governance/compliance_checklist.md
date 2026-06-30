# NĐ13/2023 Compliance Checklist — MedViet AI Platform

**Ngày đánh giá:** 30/06/2026  
**Phạm vi:** mã nguồn và artefact của bài lab `medviet-governance`  
**Quy ước:** ✅ đã triển khai và kiểm chứng · 🚧 đã thiết kế/triển khai một phần · ⬜ chưa có bằng chứng

> Checklist này đánh giá các control trong phạm vi bài lab, không phải kết luận chứng nhận tuân thủ cho môi trường production.

## A. Data Localization

- [ ] Xác nhận patient data production được lưu trên máy chủ đặt tại Việt Nam.
- [ ] Xác nhận backup, replica và disaster-recovery site đều ở Việt Nam.
- [x] Có OPA rule chặn export dữ liệu `restricted` ra ngoài Việt Nam.
- [ ] Ghi audit log cho mọi yêu cầu export/transfer và lưu bằng chứng phê duyệt.

**Bằng chứng hiện có:** `policies/opa_policy.rego`, test `test_restricted_export_outside_vietnam_is_denied`.

## B. Explicit Consent và quyền của chủ thể dữ liệu

- [ ] Thu thập consent rõ ràng trước khi dùng hồ sơ cho AI training.
- [ ] Lưu consent record gồm mục đích, phiên bản điều khoản, timestamp và trạng thái.
- [ ] Có API/workflow rút consent và ngừng sử dụng dữ liệu trong các lần training tiếp theo.
- [ ] Có workflow tra cứu, chỉnh sửa và xóa dữ liệu theo yêu cầu hợp lệ.
- [ ] Ghi lại bằng chứng xử lý yêu cầu của chủ thể dữ liệu.

**Khoảng trống:** bài lab chưa có consent store, consent API hoặc workflow right-to-erasure.

## C. Breach Detection và Notification

- [ ] Ban hành incident-response plan và ma trận mức độ sự cố.
- [ ] Thu thập metric/log và bật cảnh báo tự động cho truy cập PII bất thường.
- [ ] Tích hợp Alertmanager/SIEM với kênh trực Security 24/7.
- [ ] Có runbook cô lập, bảo toàn bằng chứng, đánh giá ảnh hưởng và thông báo trong thời hạn 72 giờ theo yêu cầu của bài lab.
- [ ] Diễn tập và lưu biên bản tối thiểu mỗi quý.

**Trạng thái:** đã thiết kế hướng triển khai; chưa có cấu hình Prometheus/Alertmanager, SIEM hoặc bằng chứng diễn tập.

## D. Data Protection Officer

- [ ] Có quyết định bổ nhiệm người/bộ phận phụ trách bảo vệ dữ liệu cá nhân.
- [ ] Công bố kênh liên hệ đã được phê duyệt.
- [ ] Xác định trách nhiệm rà soát DPIA, incident và yêu cầu của chủ thể dữ liệu.

**Liên hệ dự kiến:** `dpo@medviet.vn` — chưa được phê duyệt, không được xem là bằng chứng bổ nhiệm.

## E. Technical Control Mapping

| Control objective | Technical control | Status | Evidence | Owner |
|---|---|---|---|---|
| Data minimization | Presidio recognizers và anonymization pipeline | ✅ Done | `src/pii/`, detection rate 100% | AI Team |
| Data quality | Great Expectations suite và privacy/data-quality validation | ✅ Done | `src/quality/validation.py` | Data Team |
| Access control | Casbin RBAC, FastAPI bearer auth và default-deny OPA | ✅ Done | `src/access/`, `src/api/`, OPA 4/4 tests | Platform Team |
| Encryption at rest | Envelope encryption AES-256-GCM với DEK/KEK | ✅ Done cho local lab | `src/encryption/vault.py`, round-trip/tamper tests | Infra Team |
| Encryption in transit | TLS 1.3 tại ingress/API gateway | ⬜ Todo | Chưa có ingress/certificate config | Infra Team |
| Data localization | OPA chặn restricted export ngoài VN | 🚧 Partial | Policy đã test; chưa có bằng chứng vị trí storage/backup | Platform Team |
| Audit logging | Structured API/RBAC audit logs, immutable retention | ⬜ Todo | Chưa triển khai logger/log sink | Platform Team |
| Breach detection | Prometheus, Alertmanager và SIEM correlation | ⬜ Todo | Mới có thiết kế | Security Team |
| Secret prevention | git-secrets pre-commit, TruffleHog history scan | ✅ Done | `reports/git_secrets_report.txt`, `reports/trufflehog_report.txt` | Security Team |
| Secure code/dependencies | Bandit và pip-audit | ✅ Done | 0 Bandit issues, 0 known vulnerabilities | Security Team |

## F. Remediation Plan

| Priority | Gap | Implementation | Acceptance criteria | Owner |
|---|---|---|---|---|
| P0 | Consent management | Consent table/service với purpose, policy version, timestamp; API grant/revoke; filter revoked records khỏi training dataset | Integration test chứng minh record không có consent hoặc đã revoke không đi vào training | Product + Data |
| P0 | Audit logging | Middleware ghi `request_id`, actor/role, resource, action, decision, IP và UTC timestamp; không ghi payload PII; đẩy tới immutable storage tại VN | Mọi endpoint nhạy cảm có audit event; log tamper/retention test pass | Platform Team |
| P0 | Incident response | Alert rules, on-call routing và runbook 72 giờ; định nghĩa severity và escalation matrix | Alert test tới on-call thành công; tabletop exercise có biên bản | Security Team |
| P1 | Production key management | Chuyển KEK từ file local sang HSM/KMS tại VN; bật rotation và least-privilege IAM | Không có plaintext KEK trong host/repo; rotation và recovery test pass | Infra Team |
| P1 | TLS in transit | TLS 1.3 tại ingress, HSTS, certificate rotation và chặn HTTP plaintext | TLS scanner chỉ chấp nhận protocol/cipher đã duyệt | Infra Team |
| P1 | Data localization evidence | Inventory bucket/database/backup region; policy-as-code chặn region ngoài VN | Báo cáo inventory không có patient-data resource ngoài region được duyệt | Infra + DPO |
| P1 | Right to erasure | Workflow xác minh yêu cầu, xóa/ẩn danh ở primary store, derived dataset và backup theo retention policy | End-to-end deletion test và audit evidence pass | Data Team |
| P2 | DPO governance | Quyết định bổ nhiệm, RACI, kênh liên hệ và lịch review DPIA | Tài liệu được ban lãnh đạo phê duyệt | Legal + Management |

## G. Verification Summary

- PII detection rate: **100%**.
- Automated tests: **13 passed**.
- OPA policy tests: **4/4 passed**.
- Bandit: **0 issues**.
- pip-audit: **0 known vulnerabilities**.
- TruffleHog: **0 verified secrets**.
- git-secrets: working tree/history scan passed; hook block test passed.

Chi tiết kết quả nằm trong thư mục `reports/`.
