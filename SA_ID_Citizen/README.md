# 📱 SA-ID Citizen App — Mobile Identity Platform

![Version](https://img.shields.io/badge/version-1.0.0-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-009688)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-Private-red)
![Status](https://img.shields.io/badge/status-Phase%201%20Complete-brightgreen)

> SA citizen-facing mobile app for biometric identity verification.  
> Face scan · PIN · Document signing · SASSA grants · DHA records — all in one app.

---

## 📲 App Preview

> BankID-style mobile experience built for South African citizens.  
> Powered by SA-ID biometric backend on NVIDIA Jetson AGX Orin.

**Login Methods:**
- 🤳 Facial Recognition — live camera + liveness detection
- 🪪 Document Scan — MRZ barcode on SA-ID card
- 🔢 PIN Code — 6-digit secure PIN

**Services:**
- ✅ Verify SA-ID
- 🏛️ DHA Records
- 💰 Grant Status (SASSA)
- 📋 Payment History
- ✍️ Sign Documents (Legal / Medical / Corporate / Govt)
- ✏️ Update Contact Details
- 📎 Attach SA-ID Card
- 🚨 Report Lost / Stolen ID

---

## 🚀 Citizen App Pipelines

| Pipeline | File | Description |
|---|---|---|
| 🤳 Auth | `citizen_auth_pipeline.py` | Face, PIN, Document login |
| ✍️ Sign | `citizen_sign_pipeline.py` | Legal, Medical, Corporate, Govt signing |
| 👤 Profile | `citizen_profile_pipeline.py` | DHA lookup, update details, attach ID |
| 💰 Payments | `citizen_payments_pipeline.py` | Grant status, payment history |
| 📲 Notify | `citizen_notification_pipeline.py` | SMS, Email, Push notifications |
| 🌐 API | `main.py` | FastAPI server v3.0.0 |

---

## ⚡ Quick Start

```bash
# 1. Clone repo
git clone https://github.com/MrPitt007/SA-ID-Citizen-App.git
cd SA-ID-Citizen-App

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start server
python main.py

# 4. Open API docs
# http://127.0.0.1:8001/api/docs
```

---

## 🔑 Test Credentials

```
API Key:    test-api-key-windows-001
Test SA-ID: 8001015009087
Auth:       Bearer test-api-key-windows-001
```

---

## 📡 Citizen API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/citizen/auth/face` | Face recognition login |
| POST | `/api/v1/citizen/auth/pin` | PIN verification |
| POST | `/api/v1/citizen/auth/document` | SA-ID card scan |
| POST | `/api/v1/citizen/document/sign` | Sign a document |
| POST | `/api/v1/citizen/profile/dha` | DHA record lookup |
| POST | `/api/v1/citizen/profile/update` | Update contact details |
| POST | `/api/v1/citizen/profile/attach-id` | Attach SA-ID card |
| POST | `/api/v1/citizen/grant/status` | SASSA grant status |
| POST | `/api/v1/citizen/grant/payments` | Payment history |
| POST | `/api/v1/citizen/notify` | Send notification |

---

## 🧪 Test Examples (PowerShell)

**Face Auth:**
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8001/api/v1/citizen/auth/face" `
  -Method POST `
  -Headers @{"authorization"="Bearer test-api-key-windows-001"} `
  -ContentType "application/json" `
  -Body '{"id_number":"8001015009087","face_data_b64":null}'
```

**Sign a Document:**
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8001/api/v1/citizen/document/sign" `
  -Method POST `
  -Headers @{"authorization"="Bearer test-api-key-windows-001"} `
  -ContentType "application/json" `
  -Body '{"id_number":"8001015009087","document_type":"legal","requesting_party":"Nedbank Ltd","reference_number":"CASE-2026-001"}'
```

**Grant Status:**
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8001/api/v1/citizen/grant/status" `
  -Method POST `
  -Headers @{"authorization"="Bearer test-api-key-windows-001"} `
  -ContentType "application/json" `
  -Body '{"id_number":"8001015009087"}'
```

---

## 🗺️ Roadmap

- [x] Phase 1 — All 5 citizen pipelines built & tested
- [x] Phase 1 — FastAPI server v3.0.0
- [x] Phase 1 — Mobile app HTML (BankID-style)
- [x] Phase 1 — Document signing (Legal/Medical/Corporate/Govt)
- [ ] Phase 2 — PostgreSQL audit database
- [ ] Phase 2 — Real camera biometrics (Jetson)
- [ ] Phase 2 — React Native mobile app
- [ ] Phase 2 — CI/CD deployment pipeline

---

## 🔒 Security & Compliance

- ✅ POPIA compliant
- ✅ SHA-256 document hashing
- ✅ Blockchain audit trail
- ✅ PIN never stored in plain text
- ✅ Biometric data never stored raw
- ✅ All endpoints require Bearer token

---

> ⚠️ **Private Repository** — Proprietary technology. All rights reserved.
