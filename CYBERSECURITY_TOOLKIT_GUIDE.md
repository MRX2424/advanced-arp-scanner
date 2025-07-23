# 🔒 دليل أدوات الأمن السيبراني المتقدمة / Advanced Cybersecurity Toolkit Guide

## 📋 نظرة عامة / Overview

هذه مجموعة متقدمة من أدوات الأمن السيبراني المطورة لطلاب وممارسي الأمن السيبراني. تتضمن المجموعة أدوات متخصصة لاكتشاف الشبكات، فحص المنافذ، وتقييم أمان تطبيقات الويب.

This is an advanced collection of cybersecurity tools developed for cybersecurity students and practitioners. The toolkit includes specialized tools for network discovery, port scanning, and web application security assessment.

---

## 🛠️ الأدوات المتوفرة / Available Tools

### 1. 🔍 Enhanced ARP Scanner - ماسح ARP المتقدم

**الوصف / Description:**
أداة متقدمة لاكتشاف الأجهزة على الشبكة باستخدام بروتوكول ARP مع ميزات الإخفاء والكشف عن أنظمة التشغيل.

Advanced network discovery tool using ARP protocol with stealth capabilities and OS detection.

**الميزات الجديدة / New Features:**
- ✅ المسح متعدد الخيوط للأداء العالي / Multi-threaded scanning for high performance
- ✅ الكشف عن أنظمة التشغيل عبر TTL / OS detection via TTL analysis
- ✅ البحث عن معلومات البائع من MAC / MAC vendor lookup
- ✅ تصدير النتائج بصيغ متعددة / Multiple output formats (JSON, CSV, Table)
- ✅ وضع الإخفاء المتقدم / Advanced stealth mode
- ✅ تزوير MAC محسن / Enhanced MAC spoofing
- ✅ واجهة ملونة ومحسنة / Colored and enhanced interface

**الاستخدام / Usage:**
```bash
# المسح الأساسي / Basic scan
python3 enhanced_arp_scanner.py -r 192.168.1.1/24

# المسح مع الإخفاء وكشف نظام التشغيل / Stealth scan with OS detection
python3 enhanced_arp_scanner.py -r 192.168.1.1/24 -s -d random --os-detect --vendor-lookup

# تزوير MAC والمسح / MAC spoofing and scanning
sudo python3 enhanced_arp_scanner.py -r 192.168.1.1/24 -m -i eth0 --stealth

# حفظ النتائج / Save results
python3 enhanced_arp_scanner.py -r 192.168.1.1/24 --output json --save scan_results.json
```

---

### 2. 🚪 Advanced Port Scanner - ماسح المنافذ المتقدم

**الوصف / Description:**
أداة شاملة لفحص المنافذ مع إمكانيات الكشف عن الخدمات وتقييم الثغرات الأساسية.

Comprehensive port scanning tool with service detection and basic vulnerability assessment capabilities.

**الميزات / Features:**
- ✅ أنواع مسح متعددة / Multiple scan types (TCP Connect, SYN, UDP, etc.)
- ✅ الكشف عن الخدمات والإصدارات / Service and version detection
- ✅ تقييم الثغرات الأساسية / Basic vulnerability assessment
- ✅ المسح متعدد الخيوط / Multi-threaded scanning
- ✅ وضع الإخفاء / Stealth mode
- ✅ تحليل الشعارات (Banner Grabbing) / Banner analysis

**الاستخدام / Usage:**
```bash
# فحص المنافذ الشائعة / Scan common ports
python3 port_scanner.py -t 192.168.1.1 --common-ports

# فحص شامل مع كشف الخدمات / Comprehensive scan with service detection
python3 port_scanner.py -t 192.168.1.1 -p 1-1000 --service-detect --vuln-scan

# فحص خفي عالي الأداء / High-performance stealth scan
python3 port_scanner.py -t 192.168.1.1 -p 1-65535 --threads 100 --stealth

# فحص منافذ محددة / Scan specific ports
python3 port_scanner.py -t 192.168.1.1 -p 22,80,443,3389 --service-detect
```

---

### 3. 🌐 Web Security Scanner - ماسح أمان تطبيقات الويب

**الوصف / Description:**
أداة متقدمة لفحص ثغرات تطبيقات الويب تتضمن اختبار SQL Injection وXSS والعديد من الثغرات الأخرى.

Advanced web application vulnerability scanner including SQL Injection, XSS, and various other vulnerability tests.

**أنواع الثغرات المكتشفة / Vulnerability Types Detected:**
- 🔴 SQL Injection (حقن SQL)
- 🔴 Cross-Site Scripting (XSS)
- 🔴 Directory Traversal (اجتياز المجلدات)
- 🔴 Security Headers Analysis (تحليل رؤوس الأمان)
- 🔴 Information Disclosure (تسرب المعلومات)

**الاستخدام / Usage:**
```bash
# فحص شامل / Comprehensive scan
python3 web_security_scanner.py -u http://example.com --vuln-types all

# فحص ثغرات محددة / Specific vulnerability testing
python3 web_security_scanner.py -u http://example.com --vuln-types sql,xss

# فحص مع الزحف / Scan with crawling
python3 web_security_scanner.py -u http://example.com --crawl --depth 2

# تصدير تقرير HTML / Export HTML report
python3 web_security_scanner.py -u http://example.com --output html --save report.html
```

---

## 📦 التثبيت / Installation

```bash
# استنساخ المشروع / Clone the project
git clone https://github.com/MRX2424/advanced-arp-scanner.git
cd advanced-arp-scanner

# تثبيت المتطلبات / Install requirements
pip install -r requirements.txt

# منح صلاحيات التنفيذ / Make scripts executable
chmod +x *.py
```

---

## 🎯 تطويرات مقترحة إضافية / Additional Suggested Enhancements

### أ. أدوات جديدة مقترحة / New Proposed Tools

#### 1. 📡 **WiFi Security Scanner**
```python
# مثال للهيكل المقترح / Example proposed structure
class WiFiSecurityScanner:
    def scan_networks(self):
        # مسح شبكات WiFi المتاحة
        # Scan available WiFi networks
        pass
    
    def check_wps_vulnerability(self):
        # فحص ثغرات WPS
        # Check WPS vulnerabilities
        pass
    
    def analyze_encryption(self):
        # تحليل أنواع التشفير
        # Analyze encryption types
        pass
```

#### 2. 🔐 **Password Security Analyzer**
```python
class PasswordAnalyzer:
    def check_password_strength(self):
        # فحص قوة كلمات المرور
        # Check password strength
        pass
    
    def common_passwords_check(self):
        # فحص كلمات المرور الشائعة
        # Check against common passwords
        pass
    
    def generate_secure_password(self):
        # توليد كلمات مرور آمنة
        # Generate secure passwords
        pass
```

#### 3. 🕵️ **DNS Security Scanner**
```python
class DNSSecurityScanner:
    def dns_enumeration(self):
        # تعداد DNS
        # DNS enumeration
        pass
    
    def zone_transfer_test(self):
        # فحص نقل المناطق
        # Zone transfer testing
        pass
    
    def dns_cache_poisoning_test(self):
        # فحص تسميم ذاكرة DNS
        # DNS cache poisoning test
        pass
```

### ب. تحسينات على الأدوات الحالية / Current Tools Enhancements

#### 1. **Enhanced ARP Scanner**
- ✨ إضافة دعم IPv6 / Add IPv6 support
- ✨ تحسين دقة كشف نظام التشغيل / Improve OS detection accuracy
- ✨ إضافة قاعدة بيانات MAC أكبر / Add larger MAC vendor database
- ✨ دعم شبكات متعددة / Multiple network support

#### 2. **Port Scanner**
- ✨ إضافة مسح SYN حقيقي / Add real SYN scanning
- ✨ تحسين كشف الخدمات / Improve service detection
- ✨ إضافة مسح UDP / Add UDP scanning
- ✨ دمج مع قواعد بيانات الثغرات / Integrate with vulnerability databases

#### 3. **Web Scanner**
- ✨ إضافة اختبارات CSRF / Add CSRF testing
- ✨ فحص ثغرات SSRF / SSRF vulnerability testing
- ✨ تحليل ملفات robots.txt و sitemap / Analyze robots.txt and sitemap
- ✨ اختبار ثغرات رفع الملفات / File upload vulnerability testing

---

## 🔒 الاستخدام الأخلاقي / Ethical Usage

⚠️ **تنبيه مهم / Important Warning:**

هذه الأدوات مخصصة للأغراض التعليمية واختبار الأمان المصرح به فقط. لا تستخدم هذه الأدوات على أنظمة لا تملك إذناً صريحاً لاختبارها.

These tools are intended for educational purposes and authorized security testing only. Do not use these tools on systems you do not have explicit permission to test.

### قواعد الاستخدام الأخلاقي / Ethical Usage Guidelines:

1. **الحصول على إذن مكتوب** / Get written permission
2. **التقيد بالقوانين المحلية** / Comply with local laws
3. **عدم إلحاق الضرر** / Do no harm
4. **الإبلاغ عن الثغرات بشكل مسؤول** / Report vulnerabilities responsibly
5. **الاحتفاظ بسرية البيانات** / Maintain data confidentiality

---

## 📈 خطة التطوير المستقبلية / Future Development Plan

### المرحلة 1 (الشهر الأول) / Phase 1 (First Month):
- ✅ تطوير Enhanced ARP Scanner
- ✅ تطوير Advanced Port Scanner  
- ✅ تطوير Web Security Scanner

### المرحلة 2 (الشهر الثاني) / Phase 2 (Second Month):
- 🔄 إضافة WiFi Security Scanner
- 🔄 تطوير Password Analyzer
- 🔄 تحسين واجهة المستخدم

### المرحلة 3 (الشهر الثالث) / Phase 3 (Third Month):
- 🔄 تطوير DNS Security Scanner
- 🔄 إضافة قاعدة بيانات الثغرات
- 🔄 تطوير واجهة ويب

---

## 🤝 المساهمة / Contributing

نرحب بمساهماتكم في تطوير هذه الأدوات:

We welcome your contributions to develop these tools:

1. Fork المشروع / Fork the project
2. إنشاء فرع للميزة الجديدة / Create feature branch
3. تنفيذ التغييرات / Implement changes
4. اختبار شامل / Comprehensive testing
5. إرسال Pull Request / Submit Pull Request

---

## 📞 الدعم / Support

للدعم والاستفسارات / For support and inquiries:
- 📧 Email: [your-email@example.com]
- 💬 Issues: GitHub Issues page
- 📚 Documentation: هذا الملف / This file

---

## 📜 الرخصة / License

هذا المشروع مرخص تحت رخصة MIT - راجع ملف LICENSE للتفاصيل.

This project is licensed under the MIT License - see the LICENSE file for details.

---

## ⭐ شكر خاص / Special Thanks

شكر خاص لمجتمع الأمن السيبراني ولكل من ساهم في تطوير هذه الأدوات.

Special thanks to the cybersecurity community and everyone who contributed to developing these tools.

---

**تذكر: الأمن السيبراني مسؤولية الجميع! 🛡️**

**Remember: Cybersecurity is everyone's responsibility! 🛡️**