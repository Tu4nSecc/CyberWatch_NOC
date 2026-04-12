# SOC / Zabbix Dashboard — Kiến Trúc Hệ Thống

> Tài liệu mô tả cấu trúc dự án, vai trò từng thành phần và mối quan hệ giữa các file.

---

## 1. Tổng Quan

Hệ thống là một **SOC Dashboard** tích hợp các luồng dữ liệu bảo mật:

| Luồng | Mô tả |
|-------|-------|
| **Zabbix** | Thu thập cảnh báo & metric lịch sử qua JSON-RPC API, lưu SQLite |
| **Suricata** | Agent Linux đọc `eve.json`, đẩy sự kiện IDS về Flask API |
| **AI / ML** | Phân tích cảnh báo bằng LLM (`llm_router`) + anomaly model (`ml_model`) |
| **Lynis** | Quét hardening từ xa qua SSH, stream kết quả SSE |
| **Telegram** | Thông báo cảnh báo Zabbix theo thời gian thực |

**Điểm neo dữ liệu:** `soc_analytics.db` (SQLite) — nhiều tiến trình dùng chung.

---

## 2. Cây Thư Mục

```
NOC/
├── soc_server.py                    # Flask app chính — trung tâm điều phối
├── zabbix_client.py                 # Client JSON-RPC Zabbix
├── soc_db.py                        # Lớp SQLite (schema + CRUD)
├── ml_model.py                      # Isolation Forest + anomaly detection
├── llm_router.py                    # Gọi LLM (Gemini / Groq / OpenRouter)
├── lynis_service.py                 # SSH remote Lynis + stream SSE
├── zabbix_web_view.py               # Flask nhẹ port 5001 — xem nhanh Zabbix
├── zabbix_telegram_notifier.py      # Poll DB → gửi Telegram
├── suricata_forwarder.py            # Linux: tail eve.json → POST lên SOC
├── dashboard.html                   # Giao diện SPA (tabs: overview, AI, metrics…)
├── start_server.bat                 # Khởi động Windows
├── requirements.txt
└── soc_analytics.db                 # Tạo khi chạy, không cần commit
```

---

## 3. Vai Trò Từng File

| File | Vai trò | Phụ thuộc chính |
|------|---------|-----------------|
| `soc_server.py` | Trung tâm: REST/SSE routes, collector Zabbix, ingest Suricata, chat AI, Lynis | `zabbix_client`, `soc_db`, `ml_model`, `llm_router`, `lynis_service` |
| `zabbix_client.py` | Auth + gọi `problem.get` / `item.get` / `history.get` | Zabbix API URL |
| `soc_db.py` | Schema & CRUD SQLite: events, metrics, flows, Lynis runs | `soc_analytics.db` |
| `ml_model.py` | Huấn luyện & giải thích anomaly (IsolationForest) | `soc_db`, `sklearn`, `joblib` |
| `llm_router.py` | Chọn provider, gọi API LLM, xử lý rate limit | API keys (env) |
| `lynis_service.py` | SSH vào máy đích, chạy Lynis, parse & stream kết quả | `paramiko` |
| `zabbix_web_view.py` | App độc lập port 5001, xem nhanh dữ liệu Zabbix | Zabbix API |
| `zabbix_telegram_notifier.py` | Poll DB → lọc severity → gửi Telegram, tránh spam qua state file | `soc_db`, Telegram |
| `suricata_forwarder.py` | Đọc `eve.json`, batch POST event lên SOC | `soc_server` ingest endpoint |
| `dashboard.html` | SPA gọi `/kpis`, `/metrics`, `/chat`, v.v. | `soc_server` |

---

## 4. Luồng Dữ Liệu

### Zabbix → SQLite → Dashboard
```
ZabbixClient ──poll──► soc_server ──ghi──► soc_analytics.db
                                               ▲
dashboard.html ──GET /kpis, /metrics──────────┘
```

### AI Chat (/chat)
```
dashboard.html ──POST──► soc_server ──► llm_router ──► Gemini/Groq/OpenRouter
                                    └──► ml_model (giải thích cục bộ)
```

### Suricata → ML
```
eve.json ──► suricata_forwarder.py ──POST──► soc_server ──► soc_db ◄── ml_model
```

### Lynis SSE
```
Frontend ──POST SSH params──► soc_server ──► lynis_service ──SSH──► Linux host
         ◄────── stream SSE ─────────────────────────────────────────────────
```

### Telegram
```
soc_server ─────────────────────────────────────────────► Telegram (tức thì)
zabbix_telegram_notifier.py ──poll soc_analytics.db──►  Telegram (định kỳ)
```

---

## 5. Biến Môi Trường Chính

| Nhóm | Biến |
|------|------|
| Zabbix | `ZABBIX_API_URL`, `ZABBIX_USERNAME`, `ZABBIX_PASSWORD`, `ZABBIX_HOST_NAME` |
| Collector | `ZABBIX_POLL_INTERVAL_SEC` |
| Database | `SOC_ANALYTICS_DB_PATH` |
| LLM | `SOC_CHAT_MODE`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY` |
| Suricata | `SOC_INGEST_TOKEN`, `SOC_SERVER_URL` |
| Lynis | `LYNIS_REMOTE_ENABLED` |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `RUN_TELEGRAM_NOTIFIER` |

> ⚠️ **Không commit token/API key.** Dùng `.env` hoặc `start_server.local_env.bat` (đã có trong `.gitignore`).

---

## 6. Thứ Tự Đọc Code (Onboarding)

1. `README.md` — chạy nhanh & danh sách endpoint
2. `soc_server.py` — tìm `@app.route` để nắm API surface
3. `soc_db.py` — hiểu schema và các bảng
4. `zabbix_client.py` — tương tác JSON-RPC Zabbix
5. Tuỳ module: `ml_model.py` · `llm_router.py` · `lynis_service.py` · `suricata_forwarder.py`
