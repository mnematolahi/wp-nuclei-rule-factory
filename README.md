# WP-Nuclei-Rule-Factory

سیستم خودکار اعتبارسنجی و بسته‌بندی قوانین Nuclei مخصوص وردپرس.

---

## پیش‌نیازها

### ۱. نصب Python
- نسخه ۳.۹ یا بالاتر
- دانلود از https://python.org
- در حین نصب، گزینه **"Add Python to PATH"** را فعال کنید

### ۲. نصب Docker Desktop
- دانلود از https://docker.com/products/docker-desktop
- بعد از نصب، Docker Desktop را اجرا کنید و از طریق منوی System Tray (کنار ساعت) مطمئن شوید که **"Engine running"** است
- دستور زیر را در CMD/PowerShell بزنید تا مطمئن شوید نصب شده:
  ```bash
  docker --version
  docker ps
  ```

### ۳. نصب Nuclei
```bash
# اگر Go نصب دارید:
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# یا از releases استفاده کنید:
# https://github.com/projectdiscovery/nuclei/releases
```
بعد از نصب:
```bash
nuclei --version
```

### ۴. دریافت توکن Wordfence API
1. به https://www.wordfence.com بروید و ثبت‌نام کنید
2. از منوی حساب کاربری → **API Access** یک توکن تولید کنید
3. توکن را در فایل `config.json` در کلید `wf_api_token` قرار دهید

### ۵. نصب وابستگی‌های Python
در دایرکتوری پروژه، دستور زیر را بزنید:
```bash
pip install -r requirements.txt
```

---

## ساختار پروژه و توضیحات فایل‌ها

```
wp-nuclei-rule-factory/
│
├── wp_rule_factory.py               ← CLI اصلی: اجرای کامل pipeline (Docker SDK)
├── wp_nuclei_pipeline.py            ← جایگزین بدون Docker SDK (فقط docker CLI)
├── run_pipeline.py                  ← نسخه قدیمی pipeline (CLI-only)
├── run_local.py                     ← تست روی WordPress محلی (بدون Docker)
├── audit_templates.py               ← بررسی فیلدهای لازم در YAMLهای bulk
├── check_plugins.py                 ← بررسی وجود slug در WordPress.org
├── check_wf.py                      ← جستجو در دیتابیس Wordfence برای slug خاص
├── find_matches.py                  ← پیدا کردن تطابق بین YAMLها و Wordfence
├── _check_plugins.py                ← اسکریپت کمکی تست دانلود
│
├── wp_rule_factory/                 ← پکیج اصلی کدها
│   ├── yaml_parser.py               ← پارس YAML و استخراج slug/version
│   ├── wordfence_client.py          ← ارتباط با Wordfence API
│   ├── wp_repo.py                   ← دانلود ZIP از WordPress.org
│   ├── docker_env.py                ← مدیریت Docker با Python SDK
│   ├── docker_cli.py                ← مدیریت Docker با CLI (بدون SDK)
│   ├── nuclei_scanner.py            ← اجرای اسکن Nuclei
│   ├── packager.py                  ← ساخت پکیج خروجی
│   ├── logger.py                    ← لاگ‌گیری JSON Lines
│   └── utils.py                     ← ابزارهای مشترک
│
├── nuclei-templates/                ← قوانین Nuclei طبقه‌بندی شده بر اساس سال
├── test_yamls/                      ← فایل‌های YAML برای تست (اینجا قرار دهید)
├── verified_packages/               ← خروجی نهایی: پکیج‌های تأییدشده
└── config.json                      ← پیکربندی اصلی
```

### توضیح هر فایل اجرایی:

| فایل | چه کاری می‌کند | دستور اجرا |
|------|---------------|-----------|
| `wp_rule_factory.py` | اجرای کامل: YAML → Wordfence → دانلود → Docker → Nuclei → پکیج | `python wp_rule_factory.py --yaml-dir .\test_yamls` |
| `wp_nuclei_pipeline.py` | همانPipeline ولی بدون Docker SDK (فقط docker CLI) | `python wp_nuclei_pipeline.py --yaml-dir .\test_yamls` |
| `run_pipeline.py` | نسخه قدیمی pipeline | `python run_pipeline.py --yaml-dir .\test_yamls` |
| `run_local.py` | تست روی WordPress محلی (بدون Docker) | `python run_local.py --url http://localhost:8080 --yaml-dir .\test_yamls` |
| `audit_templates.py` | بررسی bulk: کدام YAMLها فیلدهای لازم را دارند | `python audit_templates.py --dir .\nuclei-templates` |
| `check_plugins.py` | بررسی slug در WordPress.org | `python check_plugins.py --dir .\test_yamls` |
| `find_matches.py` | پیدا کردن تطابق slugهای YAML با دیتابیس Wordfence | `python find_matches.py` |
| `check_wf.py` | جستجو در کش Wordfence برای slug خاص | `python check_wf.py` |

---

## روند کار: از صفر تا صد

### مرحله ۰ — آماده‌سازی اولیه

1. پروژه را در یک دایرکتوری کپی کنید (مثلاً `C:\Users\Nematolahi\Documents\wp-nuclei-rule-factory\wp-nuclei-rule-factory`)
2. فایل `config.json` را باز کنید و `wf_api_token` را با توکن واقعی Wordfence خود جایگزین کنید
3. Docker Desktop را اجرا کنید و مطمئن شوید Engine running است
4. وابستگی‌های Python را نصب کنید:
   ```bash
   pip install -r requirements.txt
   ```

### مرحله ۱ — قرار دادن فایل‌های YAML در پوشه تست

فایل‌های YAML قانون Nuclei خود را در پوشه `test_yamls` قرار دهید.

هر فایل YAML باید حداقل این دو فیلد را داشته باشد:
- `slug` — نامک پلاگین/قالب در WordPress.org
- `vulnerable_version` — نسخه آسیب‌پذیر (مثل `<= 5.8.5`)

مکان‌های ممکن در YAML:
```yaml
# مکان ۱: داخل variables
variables:
  slug: "contact-form-7"
  vulnerable_version: "<= 5.8.5"

# مکان ۲: داخل info.metadata
info:
  metadata:
    slug: "contact-form-7"
    vulnerable_version: "<= 5.8.5"

# مکان ۳: استخراج خودکار از info.name (مثل "Groups <= 3.10.0 - ...")
info:
  name: "Groups <= 3.10.0 - Authenticated (Contributor+) Stored XSS"
```

### مرحله ۲ — بررسی فیلدهای لازم (audit_templates.py)

```bash
python audit_templates.py --dir .\test_yamls
```

این اسکریپت چک می‌کند:
- آیا فایل YAML قابل پارس است؟
- آیا `slug` استخراج می‌شود؟
- آیا `vulnerable_version` استخراج می‌شود؟

خروجی:
- `Valid (ready)`: تعداد فایل‌های معتبر
- `Invalid (missing)`: تعداد فایل‌هایی که فیلد لازم ندارند + لیست آن‌ها

اگر همه فایل‌ها valid بودند، به مرحله بعد بروید.

### مرحله ۳ — بررسی وجود slug در WordPress.org (check_plugins.py)

```bash
python check_plugins.py --dir .\test_yamls
```

این اسکریپت:
- slugهای استخراج شده را در WordPress.org جستجو می‌کند
- نشان می‌دهد کدام slugها وجود دارند (HTTP 200) و کدام حذف شده‌اند (HTTP 404)

خروجی:
- `FOUND SLUGS`: لیست slugهای موجود + تعداد نسخه‌های آن‌ها
- `NOT FOUND SLUGS`: لیست slugهای حذف شده

**نکته:** slugهای 404 یعنی پلاگین/قالب از WordPress.org حذف شده یا slug در YAML اشتباه است. این‌ها را حذف کنید یا اصلاح کنید.

### مرحله ۴ — اجرای کامل pipeline (wp_rule_factory.py)

```bash
python wp_rule_factory.py --yaml-dir .\test_yamls
```

این دستور برای هر YAML معتبر این مراحل را انجام می‌دهد:

**مرحله ۴-۱: پارس YAML**
- استخراج `slug`, `vulnerable_version`, `rule_id`, `asset_type` و تنظیمات احراز هویت

**مرحله ۴-۲: استعلام Wordfence API**
- دیتابیس Wordfence را دانلود/کش می‌کند (`wordfence_production_db.json`)
- برای slug مورد نظر، رکورد آسیب‌پذیری را پیدا می‌کند
- نسخه‌های دقیق `vulnerable_version` و `patched_version` را استخراج می‌کند

**مرحله ۴-۳: دانلود نسخه‌ها از WordPress.org**
- ZIP نسخه آسیب‌پذیر را دانلود می‌کند + SHA256 محاسبه می‌کند
- ZIP نسخه وصله‌شده را دانلود می‌کند + SHA256 محاسبه می‌کند

**مرحله ۴-۴: تست نسخه آسیب‌پذیر در Docker**
- یک محیط Docker ایزوله (MySQL + WordPress) بالا می‌آورد
- پلاگین نسخه آسیب‌پذیر را نصب می‌کند
- Nuclei را روی آن اجرا می‌کند — **باید Match پیدا کند**

**مرحله ۴-۵: تست نسخه وصله‌شده در Docker**
- یک محیط Docker دوم بالا می‌آورد
- پلاگین نسخه patched را نصب می‌کند
- Nuclei را روی آن اجرا می‌کند — **نباید Match پیدا کند** (false positive check)

**مرحله ۴-۶: بسته‌بندی**
- اگر هر دو تست موفق بود، یک پکیج در پوشه `verified_packages` ایجاد می‌شود:
  - `rule.yaml` — YAML اصلی + annotate شده با `verified: true`
  - `vulnerable.zip` — ZIP نسخه آسیب‌پذیر
  - `patched.zip` — ZIP نسخه وصله‌شده
  - `metadata.json` — متادیتای کامل (CVE، نسخه‌ها، SHA256، خلاصه nuclei)

### مرحله ۵ — بررسی نتایج

پس از اتمام، دو فایل در پوشه `verified_packages` ایجاد می‌شوند:
- `run_*.jsonl` — لاگ کامل JSON Lines
- `run_*_summary.txt` — گزارش خلاصه انسانی

گزارش شامل:
- تعداد کل قوانین پردازش شده
- تعداد verified، rejected و failed
- برای هر قانون: دلیل rejection یا تایید

---

## خروجی نهایی

### پوشه `verified_packages/`

هر پکیج تأییدشده یک دایرکتوری جداگانه است:
```
verified_packages/
└── {rule_id}_verified_{timestamp}/
    ├── rule.yaml           ← YAML اصلی + هدر verified + metadata اضافه شده
    ├── vulnerable.zip      ← نسخه آسیب‌پذیر پلاگین/قالب
    ├── patched.zip         ← نسخه وصله‌شده پلاگین/قالب
    └── metadata.json       ← اطلاعات کامل:
                              - rule_id, verified, packaged_at
                              - slug, vulnerable_version, patched_version
                              - cve, cwe, title, severity
                              - vulnerable_sha256, patched_sha256
                              - nuclei_vuln_summary, nuclei_patched_summary
                              - test_timestamp
```

### نمونه `rule.yaml` خروجی:
```yaml
# Nuclei-Verified: true
# Validated at: 2024-09-08T12:30:00Z
# Vulnerable: contact-form-7 v5.8.5 → Patched: v5.8.6

id: wp-contact-form-7-sqli
info:
  name: "Contact Form 7 <= 5.8.5 - SQL Injection"
  severity: critical
  metadata:
    slug: "contact-form-7"
    nuclei_verified: true
    nuclei_validated_at: "2024-09-08T12:30:00Z"
    nuclei_vulnerable_version: "5.8.5"
    nuclei_patched_version: "5.8.6"
    cve: "CVE-2024-1234"
# ... بقیه محتوای YAML
```

### نمونه `metadata.json` خروجی:
```json
{
  "rule_id": "wp-contact-form-7-sqli",
  "verified": true,
  "packaged_at": "2024-09-08T12:30:05Z",
  "slug": "contact-form-7",
  "vulnerable_version": "5.8.5",
  "patched_version": "5.8.6",
  "cve": "CVE-2024-1234",
  "cwe": "CWE-89",
  "title": "Contact Form 7 <= 5.8.5 - SQL Injection",
  "severity": "critical",
  "vulnerable_sha256": "a1b2c3d4e5f6...",
  "patched_sha256": "f6e5d4c3b2a1...",
  "nuclei_vuln_summary": "1 match(es): 1x critical",
  "nuclei_patched_summary": "No matches — clean",
  "test_timestamp": "2024-09-08T12:30:00Z"
}
```

---

## عیب‌یابی رایج

### ۱. Docker not running
```bash
docker info
```
اگر خطا داد، Docker Desktop را اجرا کنید.

### ۲. Permission denied برای Docker
```bash
# در PowerShell (Admin):
sudo usermod -aG docker $USER
newgrp docker
```

### ۳. nuclei: command not found
```bash
# بررسی مسیر:
where nuclei
# یا در config.json تنظیم کنید:
# "nuclei_path": "C:\\Users\\NEMATO~1\\go\\bin\\nuclei.exe"
```

### ۴. Wordfence API returned 401/403
توکن API را در `config.json` بررسی کنید.

### ۵. Timeout waiting for WordPress
```json
// در config.json:
"container_startup_timeout": 300
```
و ایمیج‌ها را از قبل pull کنید:
```bash
docker pull wordpress:latest
docker pull mysql:8.0
```

### ۶. No match on vulnerable version
- rule可能需要 setup اضافی (import demo data، تغییر تنظیمات)
- یا matcherها خیلی generic هستند
- یا نسخه آسیب‌پذیر در WP.org وجود ندارد

### ۷. Match on PATCHED version (False Positive)
- rule بیش از حد generic است
- matcherها را دقیق‌تر کنید (مثلاً به جای `status_code: 200` از regex خاص استفاده کنید)

---

## تمیز کردن فضای داکر

بعد از تست، برای حذف فایل‌های موقت داکر:
```bash
docker system prune -f
```

اگر می‌خواهید حتی image‌های استفاده نشده هم حذف شوند (نیاز به download دوباره دارید):
```bash
docker system prune -a -f
```

---

## سوالات متداول

**Q: آیا می‌توانم بدون Docker اجرا کنم؟**
A: خیر. Docker برای ایزوله‌سازی محیط تست الزامی است. اما می‌توانید بخش‌های دیگر را با `--dry-run` تست کنید.

**Q: اگر پلاگین از WordPress.org حذف شده باشد چه؟**
A: برنامه آن قانون را رد می‌کند. می‌توانید ZIP را دستی تهیه کنید، ولی برنامه در حالت خودکار نمی‌تواند ادامه دهد.

**Q: آیا از Nuclei با پروکسی هم پشتیبانی می‌کند؟**
A: بله. می‌توانید `-proxy` را به command Nuclei در `nuclei_scanner.py` اضافه کنید.

---

## لایسنس

MIT License — برای استفاده آزاد در پروژه‌های امنیتی و تحقیقاتی.
