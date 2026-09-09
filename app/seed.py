from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models import Indicator

def now():
    return datetime.now(timezone.utc)

SAMPLE_IOCS = [
    {
        "indicator_value": "185.220.101.5",
        "indicator_type": "ipv4",
        "threat_type": "c2_server",
        "confidence_score": 95,
        "severity": "critical",
        "description": "Known Cobalt Strike Team Server detected communicating with financial sector endpoints.",
        "first_seen": now() - timedelta(days=12),
        "last_seen": now() - timedelta(hours=2),
        "is_active": True,
    },
    {
        "indicator_value": "45.154.255.88",
        "indicator_type": "ipv4",
        "threat_type": "botnet_node",
        "confidence_score": 88,
        "severity": "high",
        "description": "Mirai botnet scanning node targeting port 23/telnet and 2323.",
        "first_seen": now() - timedelta(days=30),
        "last_seen": now() - timedelta(hours=6),
        "is_active": True,
    },
    {
        "indicator_value": "login.microsoft-auth-verify.com",
        "indicator_type": "domain",
        "threat_type": "credential_harvesting",
        "confidence_score": 92,
        "severity": "critical",
        "description": "Typosquatted domain hosting EvilProxy reverse proxy targeting Office 365 MFA.",
        "first_seen": now() - timedelta(days=3),
        "last_seen": now() - timedelta(minutes=45),
        "is_active": True,
    },
    {
        "indicator_value": "secure-payroll-update.top",
        "indicator_type": "domain",
        "threat_type": "phishing",
        "confidence_score": 78,
        "severity": "medium",
        "description": "HR-themed spearphishing lure delivering disguised malicious SVG attachments.",
        "first_seen": now() - timedelta(days=5),
        "last_seen": now() - timedelta(days=1),
        "is_active": True,
    },
    {
        "indicator_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "indicator_type": "sha256",
        "threat_type": "ransomware_payload",
        "confidence_score": 99,
        "severity": "critical",
        "description": "LockBit 3.0 ransomware executable encryptor dropping ransom notes.",
        "first_seen": now() - timedelta(days=45),
        "last_seen": now() - timedelta(days=2),
        "is_active": True,
    },
    {
        "indicator_value": "https://cdn.discordapp.com/attachments/malicious/loader.exe",
        "indicator_type": "url",
        "threat_type": "malware_delivery",
        "confidence_score": 65,
        "severity": "medium",
        "description": "Abused Discord CDN link hosting RedLine Stealer payload.",
        "first_seen": now() - timedelta(days=2),
        "last_seen": now() - timedelta(hours=14),
        "is_active": True,
    }
]

def seed_threat_data(db: Session):
    """Seeds initial threat intelligence indicators if table is empty."""
    # ⚡ Bolt Optimization:
    # Replaced O(N) db.query(Indicator).count() with O(1) .first() existence check.
    # .count() causes a full table scan or index scan, while .first() returns instantly
    # after finding the first row. This dramatically speeds up startup on large DBs.
    exists = db.query(Indicator.id).first() is not None
    if not exists:
        for ioc_data in SAMPLE_IOCS:
            ioc = Indicator(**ioc_data)
            db.add(ioc)
        db.commit()
        print(f"[*] Seeded {len(SAMPLE_IOCS)} initial threat indicators into database.")
