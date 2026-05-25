# AI-Powered SOC Automation Platform

Splunk, Python ve Claude AI kullanarak geliştirilmiş 
modüler bir AI destekli SOC otomasyon platformu.

## Mimari

Windows Host (Log Kaynağı)
↓ Universal Forwarder
Ubuntu VM (Splunk Enterprise)
↓ REST API
Python (Anomali Tespiti)
↓ Claude API
AI Analiz + SOAR Playbook

## Modüller

- ✅Splunk Brute Force Detection Dashboard - İleride daha da genişletilecek..
- ✅ Risk Skorlama (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ Python + Splunk API Entegrasyonu
- ✅ Claude AI Tehdit Analizi
- ✅ Otomatik Email Bildirimi
- ✅ Incident Log Sistemi
- 🔄Log Normalizasyonu (devam ediyor)
- 🔄MITRE ATT&CK Threat Hunting
- 🔄Korelasyon Kuralları

## Tech Stack

- Splunk Enterprise 9.3
- Python 3.10
- Claude Sonnet API (Anthropic) - Opus'a dönüştürülebilir
- Ubuntu Server 22.04
- Windows 10/11

## Kurulum

1. `.env.example` dosyasını `.env` olarak kopyala
2. Gerekli değerleri doldur
3. `pip3 install -r requirements.txt`
4. `python3 soar_playbook.py`
