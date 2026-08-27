#!/usr/bin/env python3

import asyncio
import ctypes
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings

APP_NAME = "CertGraph"
APP_VERSION = "1.0.0"
BANNER = r"""
   ______           __  ______                 __
  / ____/__  _____/ /_/ ____/________ _____  / /_
 / /   / _ \/ ___/ __/ / __/ ___/ __ `/ __ \/ __/
/ /___/  __/ /  / /_/ /_/ / /  / /_/ / /_/ / /_
\____/\___/_/   \__/\____/_/   \__,_/ .___/\__/
                                   /_/
        Certificate Intelligence 
                    v{version} | 
""".format(version=APP_VERSION)


class Settings(BaseSettings):
    host: str = "127.0.0.1"
    port: int = 8443
    db_path: str = "data/certgraph.db"
    max_workers: int = 32
    connect_timeout: float = 8.0
    max_targets: int = 500
    max_scan_work: int = 2000
    rate_limit_per_host: float = 0.15
    log_level: str = "INFO"
    api_token: Optional[str] = None
    scan_requests_per_minute: int = 20

    class Config:
        env_prefix = "CERTGRAPH_"


settings = Settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(APP_NAME)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("uvicorn.error").setLevel(logging.INFO)

WEAK_SIGNATURE_ALGORITHMS = {
    "md5", "sha1", "md2", "md4",
    "sha1WithRSAEncryption", "md5WithRSAEncryption",
}
WEAK_KEY_SIZES = {
    "rsa": 2048,
    "dsa": 2048,
    "ec": 256,
}
KNOWN_UNTRUSTED_ISSUERS = {
    "startcom", "wosign", "certinomis", "symantec",
    "thawte", "geotrust", "rapidssl", "verisign",
}
SUSPICIOUS_CN_PATTERNS = [
    re.compile(r"(?i)(localhost|127\.0\.0\.1|::1|internal|test|dev|staging)"),
    re.compile(r"(?i)(self[-_]?signed|dummy|placeholder|example\.com)"),
]
PRIVATE_HOST_PATTERNS = [
    re.compile(r"(?i)^(localhost|.*\.local|.*\.internal|.*\.lan|.*\.home)$"),
]


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


def _is_private_scope(host: str) -> bool:
    if _is_ip(host):
        try:
            return ipaddress.ip_address(host).is_private
        except ValueError:
            return False
    return any(p.match(host) for p in PRIVATE_HOST_PATTERNS)


def _extract_host_from_authority(t: str) -> Optional[str]:
    if t.startswith("["):
        end = t.find("]")
        if end != -1:
            return t[1:end]
        return None
    if t.count(":") > 1:
        return t
    return t.split(":")[0]


class TargetInput(BaseModel):
    targets: List[str] = Field(..., min_length=1, max_length=settings.max_targets)
    ports: List[int] = Field(default=[443], min_length=1, max_length=20)
    deep_chain: bool = True
    analyze_vulns: bool = True

    @field_validator("targets")
    @classmethod
    def normalize_targets(cls, v: List[str]) -> List[str]:
        cleaned: List[str] = []
        seen: Set[str] = set()
        for raw in v:
            t = raw.strip().lower()
            if not t or any(ord(ch) < 0x20 for ch in t):
                continue
            if "://" in t:
                parsed = urlparse(t)
                host = parsed.hostname or ""
            else:
                host = _extract_host_from_authority(t) or ""
                host = host.split("/")[0]
            host = host.strip(".")
            if not host or len(host) > 253:
                continue
            if not _is_ip(host) and not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$", host):
                continue
            if host not in seen:
                seen.add(host)
                cleaned.append(host)
        if not cleaned:
            raise ValueError("No valid targets after filtering")
        return cleaned

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: List[int]) -> List[int]:
        out = sorted({p for p in v if 1 <= p <= 65535})
        if not out:
            raise ValueError("No valid ports")
        return out

    @model_validator(mode="after")
    def check_total_work(self) -> "TargetInput":
        total = len(self.targets) * len(self.ports)
        if total > settings.max_scan_work:
            raise ValueError(
                f"Requested scan work ({total} target/port combinations) exceeds the limit of {settings.max_scan_work}"
            )
        return self


class Database:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = self._open()
        self._init_schema()

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    target_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running'
                );
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    subject_cn TEXT,
                    issuer_cn TEXT,
                    serial_number TEXT,
                    not_before TEXT,
                    not_after TEXT,
                    signature_algorithm TEXT,
                    key_type TEXT,
                    key_size INTEGER,
                    is_self_signed INTEGER DEFAULT 0,
                    is_ca INTEGER DEFAULT 0,
                    sans TEXT,
                    chain_length INTEGER DEFAULT 1,
                    spki_fingerprint TEXT,
                    raw_pem TEXT,
                    collected_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id),
                    UNIQUE(scan_id, host, port, fingerprint_sha256)
                );
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cert_id INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    confidence REAL DEFAULT 1.0,
                    FOREIGN KEY (cert_id) REFERENCES certificates(id)
                );
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    node_id TEXT NOT NULL,
                    label TEXT,
                    node_type TEXT,
                    properties TEXT,
                    UNIQUE(scan_id, node_id)
                );
                CREATE TABLE IF NOT EXISTS graph_edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    target TEXT NOT NULL,
                    edge_type TEXT,
                    properties TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_cert_fp ON certificates(fingerprint_sha256);
                CREATE INDEX IF NOT EXISTS idx_cert_host ON certificates(host);
                CREATE INDEX IF NOT EXISTS idx_cert_spki ON certificates(spki_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_vuln_cert ON vulnerabilities(cert_id);
            """)

    def create_scan(self, target_count: int) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO scans (started_at, target_count, status) VALUES (?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), target_count, "running"),
            )
            return cur.lastrowid

    def finish_scan(self, scan_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET finished_at = ?, status = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), "completed", scan_id),
            )

    def store_certificate(self, scan_id: int, data: Dict[str, Any]) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO certificates (
                    scan_id, host, port, fingerprint_sha256, subject_cn, issuer_cn,
                    serial_number, not_before, not_after, signature_algorithm,
                    key_type, key_size, is_self_signed, is_ca, sans, chain_length,
                    spki_fingerprint, raw_pem, collected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    data["host"],
                    data["port"],
                    data["fingerprint_sha256"],
                    data.get("subject_cn"),
                    data.get("issuer_cn"),
                    data.get("serial_number"),
                    data.get("not_before"),
                    data.get("not_after"),
                    data.get("signature_algorithm"),
                    data.get("key_type"),
                    data.get("key_size"),
                    1 if data.get("is_self_signed") else 0,
                    1 if data.get("is_ca") else 0,
                    json.dumps(data.get("sans") or []),
                    data.get("chain_length", 1),
                    data.get("spki_fingerprint"),
                    data.get("raw_pem"),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            if cur.lastrowid:
                return cur.lastrowid
            row = self._conn.execute(
                "SELECT id FROM certificates WHERE scan_id=? AND host=? AND port=? AND fingerprint_sha256=?",
                (scan_id, data["host"], data["port"], data["fingerprint_sha256"]),
            ).fetchone()
            return row["id"] if row else 0

    def store_vulnerabilities(self, cert_id: int, vulns: List[Dict[str, Any]]) -> None:
        if not vulns or not cert_id:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                """
                INSERT INTO vulnerabilities (cert_id, severity, category, title, description, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        cert_id,
                        v["severity"],
                        v["category"],
                        v["title"],
                        v.get("description", ""),
                        v.get("confidence", 1.0),
                    )
                    for v in vulns
                ],
            )

    def certs_by_spki(self, scan_id: int) -> Dict[str, List[int]]:
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT id, spki_fingerprint FROM certificates WHERE scan_id=? AND spki_fingerprint IS NOT NULL",
                (scan_id,),
            ).fetchall()
        grouped: Dict[str, List[int]] = {}
        for r in rows:
            grouped.setdefault(r["spki_fingerprint"], []).append(r["id"])
        return grouped

    def store_graph(self, scan_id: int, nodes: List[Dict], edges: List[Dict]) -> None:
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT OR REPLACE INTO graph_nodes (scan_id, node_id, label, node_type, properties) VALUES (?, ?, ?, ?, ?)",
                [
                    (scan_id, n["id"], n.get("label"), n.get("type"), json.dumps(n.get("properties") or {}))
                    for n in nodes
                ],
            )
            self._conn.executemany(
                "INSERT INTO graph_edges (scan_id, source, target, edge_type, properties) VALUES (?, ?, ?, ?, ?)",
                [
                    (scan_id, e["source"], e["target"], e.get("type"), json.dumps(e.get("properties") or {}))
                    for e in edges
                ],
            )

    def get_scan_results(self, scan_id: int) -> Dict[str, Any]:
        with self._lock, self._conn:
            scan = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not scan:
                return {}
            certs = [dict(r) for r in self._conn.execute(
                "SELECT * FROM certificates WHERE scan_id=? ORDER BY host", (scan_id,)
            ).fetchall()]
            for c in certs:
                c["sans"] = json.loads(c["sans"] or "[]")
                c["vulnerabilities"] = [
                    dict(v) for v in self._conn.execute(
                        "SELECT severity, category, title, description, confidence FROM vulnerabilities WHERE cert_id=?",
                        (c["id"],),
                    ).fetchall()
                ]
            nodes = [dict(r) for r in self._conn.execute(
                "SELECT node_id as id, label, node_type as type, properties FROM graph_nodes WHERE scan_id=?",
                (scan_id,),
            ).fetchall()]
            for n in nodes:
                n["properties"] = json.loads(n["properties"] or "{}")
            edges = [dict(r) for r in self._conn.execute(
                "SELECT source, target, edge_type as type, properties FROM graph_edges WHERE scan_id=?",
                (scan_id,),
            ).fetchall()]
            for e in edges:
                e["properties"] = json.loads(e["properties"] or "{}")
            return {
                "scan": dict(scan),
                "certificates": certs,
                "graph": {"nodes": nodes, "edges": edges},
            }

    def list_scans(self, limit: int = 50) -> List[Dict]:
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT id, started_at, finished_at, target_count, status FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]


db = Database(settings.db_path)


class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self.active:
                self.active.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        payload = json.dumps(message, default=str)
        async with self._lock:
            targets = list(self.active)
        dead = []
        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    if ws in self.active:
                        self.active.remove(ws)


manager = ConnectionManager()


class ScanRateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = max(1, per_minute)
        self._lock = threading.Lock()
        self._hits: Dict[str, List[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window_start = now - 60.0
        with self._lock:
            hits = [h for h in self._hits.get(key, []) if h > window_start]
            if len(hits) >= self.per_minute:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


scan_rate_limiter = ScanRateLimiter(settings.scan_requests_per_minute)


def _get_cn(name: x509.Name) -> Optional[str]:
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return str(attrs[0].value)
    except Exception:
        pass
    return None


def _get_org(name: x509.Name) -> Optional[str]:
    try:
        attrs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if attrs:
            return str(attrs[0].value)
    except Exception:
        pass
    return None


def _extract_sans(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [str(n.value) for n in ext.value]
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []


def _key_info(public_key) -> Tuple[str, int]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "dsa", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ec", public_key.curve.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "ed448", 456
    return "unknown", 0


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        return bool(ext.value.ca)
    except Exception:
        return False


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _spki_fingerprint(cert: x509.Certificate) -> Optional[str]:
    try:
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(spki).hexdigest()
    except Exception:
        return None


def _has_sct(cert: x509.Certificate) -> bool:
    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS)
        return True
    except x509.ExtensionNotFound:
        return False
    except Exception:
        return False


def _eku_has_server_auth(cert: x509.Certificate) -> Optional[bool]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        return ExtendedKeyUsageOID.SERVER_AUTH in ext.value
    except x509.ExtensionNotFound:
        return None
    except Exception:
        return None


def _is_admin() -> bool:
    system = platform.system()
    if system == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _analyze_vulnerabilities(chain: List[x509.Certificate], host: str) -> List[Dict[str, Any]]:
    vulns: List[Dict[str, Any]] = []
    if not chain:
        return vulns
    now = datetime.now(timezone.utc)
    leaf = chain[0]
    subject_cn = _get_cn(leaf.subject) or ""
    issuer_cn = _get_cn(leaf.issuer) or ""
    issuer_org = (_get_org(leaf.issuer) or "").lower()
    sig_alg = str(leaf.signature_hash_algorithm.name) if leaf.signature_hash_algorithm else str(
        getattr(leaf.signature_algorithm_oid, "_name", "unknown")
    )
    key_type, key_size = _key_info(leaf.public_key())
    is_self = leaf.subject == leaf.issuer
    sans = _extract_sans(leaf)
    is_private_target = _is_private_scope(host)

    if leaf.not_valid_after_utc < now:
        days = (now - leaf.not_valid_after_utc).days
        vulns.append({
            "severity": "critical" if days > 30 else "high",
            "category": "expiration",
            "title": "Certificate Expired",
            "description": f"Expired {days} day(s) ago on {leaf.not_valid_after_utc.isoformat()}",
            "confidence": 1.0,
        })
    elif (leaf.not_valid_after_utc - now).days <= 14:
        vulns.append({
            "severity": "medium",
            "category": "expiration",
            "title": "Certificate Expiring Soon",
            "description": f"Expires in {(leaf.not_valid_after_utc - now).days} day(s)",
            "confidence": 1.0,
        })

    if leaf.not_valid_before_utc > now:
        vulns.append({
            "severity": "high",
            "category": "validity",
            "title": "Certificate Not Yet Valid",
            "description": f"Valid from {leaf.not_valid_before_utc.isoformat()}",
            "confidence": 1.0,
        })

    sig_lower = sig_alg.lower()
    if any(w in sig_lower for w in WEAK_SIGNATURE_ALGORITHMS):
        vulns.append({
            "severity": "high",
            "category": "cryptography",
            "title": "Weak Signature Algorithm",
            "description": f"Leaf certificate uses {sig_alg}, which is considered weak",
            "confidence": 0.95,
        })

    min_size = WEAK_KEY_SIZES.get(key_type, 0)
    if min_size and key_size and key_size < min_size:
        vulns.append({
            "severity": "high" if key_size < 1024 else "medium",
            "category": "cryptography",
            "title": "Insufficient Key Size",
            "description": f"{key_type.upper()} key of {key_size} bits is below recommended {min_size}",
            "confidence": 0.98,
        })

    if is_self:
        confidence = 0.85
        for pat in SUSPICIOUS_CN_PATTERNS:
            if pat.search(subject_cn) or pat.search(host):
                confidence = 0.99
                break
        if is_private_target:
            confidence = min(confidence, 0.6)
        vulns.append({
            "severity": "medium",
            "category": "trust",
            "title": "Self-Signed Certificate",
            "description": "Certificate is self-signed and not issued by a trusted CA",
            "confidence": confidence,
        })

    if any(u in issuer_org or u in issuer_cn.lower() for u in KNOWN_UNTRUSTED_ISSUERS):
        vulns.append({
            "severity": "high",
            "category": "trust",
            "title": "Untrusted or Deprecated Issuer",
            "description": f"Issuer '{issuer_cn}' is associated with historically untrusted or deprecated CAs",
            "confidence": 0.85,
        })

    if not sans and not _is_ip(host):
        vulns.append({
            "severity": "low",
            "category": "configuration",
            "title": "Missing Subject Alternative Names",
            "description": "No SAN extension present; modern clients require SANs",
            "confidence": 0.9,
        })
    elif host and not _is_ip(host):
        host_matched = any(
            s.lower() == host or (s.startswith("*.") and host.endswith(s[1:]))
            for s in sans
        )
        if not host_matched and subject_cn.lower() != host:
            vulns.append({
                "severity": "medium",
                "category": "configuration",
                "title": "Hostname Mismatch",
                "description": f"Neither CN nor SANs match requested host '{host}'",
                "confidence": 0.92,
            })

    if _is_ca(leaf):
        vulns.append({
            "severity": "high",
            "category": "configuration",
            "title": "Leaf Certificate Flagged as CA",
            "description": "The server's leaf certificate has CA:TRUE in its basic constraints",
            "confidence": 0.9,
        })

    eku = _eku_has_server_auth(leaf)
    if eku is False:
        vulns.append({
            "severity": "medium",
            "category": "configuration",
            "title": "Missing serverAuth Extended Key Usage",
            "description": "Extended Key Usage extension is present but does not authorize TLS server authentication",
            "confidence": 0.9,
        })

    if not is_self and not is_private_target and not _has_sct(leaf):
        vulns.append({
            "severity": "low",
            "category": "transparency",
            "title": "Missing Certificate Transparency SCTs",
            "description": "No embedded Signed Certificate Timestamps found",
            "confidence": 0.6,
        })

    if len(chain) == 1 and not is_self:
        vulns.append({
            "severity": "low",
            "category": "chain",
            "title": "Incomplete Certificate Chain",
            "description": "Only the leaf certificate was returned; no intermediate certificates were presented",
            "confidence": 0.75,
        })

    try:
        ku = leaf.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        if not ku.value.digital_signature and not ku.value.key_encipherment:
            vulns.append({
                "severity": "medium",
                "category": "usage",
                "title": "Restrictive Key Usage",
                "description": "Key usage does not include digitalSignature or keyEncipherment",
                "confidence": 0.7,
            })
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    for position, cert in enumerate(chain[1:], start=1):
        role = "Root CA" if cert.subject == cert.issuer else "Intermediate CA"
        is_root = role == "Root CA"
        c_key_type, c_key_size = _key_info(cert.public_key())
        c_min_size = WEAK_KEY_SIZES.get(c_key_type, 0)
        if c_min_size and c_key_size and c_key_size < c_min_size:
            vulns.append({
                "severity": "medium" if is_root else "high",
                "category": "cryptography",
                "title": f"Weak {role} Key Size",
                "description": f"{role} at chain position {position} uses a {c_key_type.upper()} key of {c_key_size} bits",
                "confidence": 0.9 if is_root else 0.95,
            })
        if not is_root:
            c_sig = str(cert.signature_hash_algorithm.name) if cert.signature_hash_algorithm else ""
            if any(w in c_sig.lower() for w in WEAK_SIGNATURE_ALGORITHMS):
                vulns.append({
                    "severity": "high",
                    "category": "cryptography",
                    "title": "Weak Intermediate Signature Algorithm",
                    "description": f"Intermediate CA at chain position {position} uses {c_sig}, which is considered weak",
                    "confidence": 0.9,
                })
        if cert.not_valid_after_utc < now:
            vulns.append({
                "severity": "high",
                "category": "chain",
                "title": f"Expired {role}",
                "description": f"{role} at chain position {position} expired on {cert.not_valid_after_utc.isoformat()}",
                "confidence": 0.95,
            })

    return vulns


def _fetch_certificate(host: str, port: int, timeout: float) -> Tuple[Optional[Dict[str, Any]], Optional[str], List[x509.Certificate]]:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host if not _is_ip(host) else None) as ssock:
                der_list: List[bytes] = []
                get_chain = getattr(ssock, "get_unverified_chain", None)
                if callable(get_chain):
                    try:
                        chain_objs = get_chain()
                        if chain_objs:
                            der_list = [
                                c.public_bytes() if hasattr(c, "public_bytes") else c
                                for c in chain_objs
                            ]
                    except Exception:
                        der_list = []
                if not der_list:
                    try:
                        peercert = ssock.getpeercert(binary_form=True)
                        if peercert:
                            der_list = [peercert]
                    except Exception:
                        der_list = []
                if not der_list:
                    return None, "No certificate received", []
                certs: List[x509.Certificate] = []
                for der in der_list:
                    try:
                        certs.append(x509.load_der_x509_certificate(der, default_backend()))
                    except Exception:
                        continue
                if not certs:
                    return None, "Failed to parse certificate", []
                leaf = certs[0]
                fp = _fingerprint(leaf)
                key_type, key_size = _key_info(leaf.public_key())
                sig_alg = "unknown"
                try:
                    if leaf.signature_hash_algorithm:
                        sig_alg = leaf.signature_hash_algorithm.name
                    else:
                        sig_alg = str(leaf.signature_algorithm_oid._name)
                except Exception:
                    pass
                pem = leaf.public_bytes(serialization.Encoding.PEM).decode("ascii", errors="replace")
                data = {
                    "host": host,
                    "port": port,
                    "fingerprint_sha256": fp,
                    "subject_cn": _get_cn(leaf.subject),
                    "issuer_cn": _get_cn(leaf.issuer),
                    "issuer_org": _get_org(leaf.issuer),
                    "serial_number": format(leaf.serial_number, "x"),
                    "not_before": leaf.not_valid_before_utc.isoformat(),
                    "not_after": leaf.not_valid_after_utc.isoformat(),
                    "signature_algorithm": sig_alg,
                    "key_type": key_type,
                    "key_size": key_size,
                    "is_self_signed": leaf.subject == leaf.issuer,
                    "is_ca": _is_ca(leaf),
                    "sans": _extract_sans(leaf),
                    "chain_length": len(certs),
                    "spki_fingerprint": _spki_fingerprint(leaf),
                    "raw_pem": pem,
                    "chain_fps": [_fingerprint(c) for c in certs],
                }
                return data, None, certs
    except socket.timeout:
        return None, "Connection timed out", []
    except socket.gaierror:
        return None, "DNS resolution failed", []
    except ConnectionRefusedError:
        return None, "Connection refused", []
    except ssl.SSLError as e:
        return None, f"SSL error: {str(e)[:120]}", []
    except OSError as e:
        return None, f"Network error: {str(e)[:120]}", []
    except Exception as e:
        return None, f"Unexpected error: {type(e).__name__}", []


def build_graph(results: List[Dict[str, Any]]) -> Tuple[List[Dict], List[Dict]]:
    nodes: Dict[str, Dict] = {}
    edges: List[Dict] = []
    seen_edges: Set[Tuple[str, str, str]] = set()

    def add_node(nid: str, label: str, ntype: str, props: Optional[Dict] = None):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "type": ntype, "properties": props or {}}

    def add_edge(source: str, target: str, etype: str):
        key = (source, target, etype)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({"source": source, "target": target, "type": etype})

    for r in results:
        if not r.get("success"):
            continue
        host = r["host"]
        port = r["port"]
        fp = r["fingerprint_sha256"]
        host_id = f"host:{host}"
        cert_id = f"cert:{fp[:16]}"
        chain_summary = r.get("chain_summary") or []

        add_node(host_id, host, "host", {"port": port})
        add_node(
            cert_id,
            r.get("subject_cn") or fp[:12],
            "certificate",
            {
                "fingerprint": fp,
                "key": f"{r.get('key_type', '?')}-{r.get('key_size', 0)}",
                "expires": r.get("not_after"),
                "self_signed": r.get("is_self_signed"),
            },
        )
        add_edge(host_id, cert_id, "presents")

        prev_id = cert_id
        if chain_summary:
            for idx, member in enumerate(chain_summary):
                label = member.get("subject_cn") or member.get("fingerprint", "")[:12] or "Unknown CA"
                node_type = "root_ca" if member.get("is_self_signed") else "intermediate_ca"
                member_id = f"ca:{member.get('fingerprint', str(idx))[:16]}"
                add_node(member_id, label, node_type, {
                    "fingerprint": member.get("fingerprint"),
                    "key": f"{member.get('key_type', '?')}-{member.get('key_size', 0)}",
                })
                add_edge(prev_id, member_id, "issued_by")
                prev_id = member_id
        else:
            issuer = r.get("issuer_cn") or "Unknown Issuer"
            issuer_id = f"issuer:{hashlib.sha256(issuer.encode()).hexdigest()[:12]}"
            add_node(issuer_id, issuer, "issuer", {"org": r.get("issuer_org")})
            add_edge(cert_id, issuer_id, "issued_by")

        for san in r.get("sans") or []:
            if san.startswith("*."):
                continue
            san_id = f"san:{san}"
            add_node(san_id, san, "san")
            add_edge(cert_id, san_id, "covers")

        for v in r.get("vulnerabilities") or []:
            if v.get("severity") in ("critical", "high"):
                vid = f"vuln:{fp[:8]}:{v['category']}:{v['title'][:24]}"
                add_node(vid, v["title"], "vulnerability", {"severity": v["severity"]})
                add_edge(cert_id, vid, "has_issue")

    return list(nodes.values()), edges


async def run_scan(targets: List[str], ports: List[int], deep: bool, analyze: bool, scan_id: int) -> None:
    total = len(targets) * len(ports)
    completed = 0
    results: List[Dict[str, Any]] = []
    cert_id_map: Dict[Tuple[str, int], int] = {}
    executor = ThreadPoolExecutor(max_workers=min(settings.max_workers, max(total, 1)))
    loop = asyncio.get_running_loop()
    last_host_time: Dict[str, float] = {}
    completed_lock = asyncio.Lock()

    async def process_one(host: str, port: int) -> None:
        nonlocal completed
        entry: Dict[str, Any] = {
            "host": host,
            "port": port,
            "success": False,
            "error": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            now = time.monotonic()
            last = last_host_time.get(host, 0.0)
            delay = settings.rate_limit_per_host - (now - last)
            if delay > 0:
                await asyncio.sleep(delay)
            last_host_time[host] = time.monotonic()

            data, err, chain_certs = await loop.run_in_executor(
                executor, _fetch_certificate, host, port, settings.connect_timeout
            )
            entry["success"] = data is not None
            entry["error"] = err
            if data:
                entry.update(data)
                if analyze and chain_certs:
                    try:
                        entry["vulnerabilities"] = _analyze_vulnerabilities(chain_certs, host)
                    except Exception:
                        logger.warning("Analysis failed for %s:%s", host, port)
                        entry["vulnerabilities"] = []
                else:
                    entry["vulnerabilities"] = []
                if len(chain_certs) > 1:
                    entry["chain_summary"] = [
                        {
                            "subject_cn": _get_cn(c.subject),
                            "fingerprint": _fingerprint(c),
                            "is_self_signed": c.subject == c.issuer,
                            "key_type": _key_info(c.public_key())[0],
                            "key_size": _key_info(c.public_key())[1],
                        }
                        for c in chain_certs[1:]
                    ]
                try:
                    cert_id = db.store_certificate(scan_id, data)
                except Exception:
                    logger.error("Failed to persist certificate for %s:%s", host, port)
                    cert_id = 0
                if cert_id:
                    cert_id_map[(host, port)] = cert_id
                    if entry.get("vulnerabilities"):
                        try:
                            db.store_vulnerabilities(cert_id, entry["vulnerabilities"])
                        except Exception:
                            logger.error("Failed to persist findings for %s:%s", host, port)
        except Exception:
            logger.exception("Unhandled error scanning %s:%s", host, port)
            entry["success"] = False
            entry["error"] = "Internal scan error"
        finally:
            results.append(entry)
            async with completed_lock:
                completed += 1
                current = completed
            await manager.broadcast({
                "type": "progress",
                "scan_id": scan_id,
                "completed": current,
                "total": total,
                "percent": round(100.0 * current / total, 1) if total else 100,
                "result": entry,
            })

    tasks = [process_one(h, p) for h in targets for p in ports]
    await asyncio.gather(*tasks, return_exceptions=True)
    executor.shutdown(wait=False)

    try:
        spki_groups = db.certs_by_spki(scan_id)
        for spki, cert_ids in spki_groups.items():
            if len(cert_ids) < 2:
                continue
            finding = [{
                "severity": "medium",
                "category": "trust",
                "title": "Private Key Reused Across Certificates",
                "description": f"The same public key material appears in {len(cert_ids)} certificates collected in this scan",
                "confidence": 0.8,
            }]
            for cert_id in cert_ids:
                db.store_vulnerabilities(cert_id, finding)
            for entry in results:
                if cert_id_map.get((entry.get("host"), entry.get("port"))) in cert_ids:
                    entry.setdefault("vulnerabilities", []).extend(finding)
    except Exception:
        logger.error("Cross-host key reuse analysis failed for scan %s", scan_id)

    nodes, edges = build_graph(results)
    db.store_graph(scan_id, nodes, edges)
    db.finish_scan(scan_id)

    await manager.broadcast({
        "type": "complete",
        "scan_id": scan_id,
        "total": total,
        "success_count": sum(1 for r in results if r.get("success")),
        "graph": {"nodes": nodes, "edges": edges},
        "summary": {
            "critical": sum(1 for r in results for v in r.get("vulnerabilities") or [] if v.get("severity") == "critical"),
            "high": sum(1 for r in results for v in r.get("vulnerabilities") or [] if v.get("severity") == "high"),
            "medium": sum(1 for r in results for v in r.get("vulnerabilities") or [] if v.get("severity") == "medium"),
            "low": sum(1 for r in results for v in r.get("vulnerabilities") or [] if v.get("severity") == "low"),
        },
    })


def verify_token(x_api_token: Optional[str] = Header(None), token: Optional[str] = Query(None)) -> None:
    if not settings.api_token:
        return
    supplied = x_api_token or token or ""
    if not secrets.compare_digest(supplied, settings.api_token):
        raise HTTPException(status_code=401, detail="Invalid or missing API token")


async def verify_ws_token(websocket: WebSocket) -> bool:
    if not settings.api_token:
        return True
    supplied = websocket.query_params.get("token") or websocket.headers.get("x-api-token") or ""
    return secrets.compare_digest(supplied, settings.api_token)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(BANNER)
    templates_dir = Path(__file__).parent / "templates"
    if not (templates_dir / "index.html").exists():
        logger.error("Missing templates/index.html next to certgraph.py; refusing to start")
        raise SystemExit(1)
    if platform.system() != "Windows" and settings.port < 1024 and not _is_admin():
        logger.error(
            "Binding to port %s requires elevated privileges on this platform. "
            "Run with sudo, use setcap, or choose a port >= 1024.",
            settings.port,
        )
        raise SystemExit(1)
    logger.info("%s %s starting on %s:%s (%s)", APP_NAME, APP_VERSION, settings.host, settings.port, platform.system())
    if settings.host not in ("127.0.0.1", "localhost", "::1") and not settings.api_token:
        logger.warning("Listening on %s without an API token configured; set CERTGRAPH_API_TOKEN to restrict access", settings.host)
    yield
    db.close()
    logger.info("%s shutdown", APP_NAME)


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan, docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, token: Optional[str] = Query(None)):
    if settings.api_token and token != settings.api_token:
        raise HTTPException(status_code=401, detail="Invalid or missing API token")
    return templates.TemplateResponse(request, "index.html", {
        "app_name": APP_NAME,
        "version": APP_VERSION,
        "api_token": settings.api_token or "",
    })


@app.post("/api/scan", dependencies=[Depends(verify_token)])
async def start_scan(payload: TargetInput, request: Request):
    client_key = request.client.host if request.client else "unknown"
    if not scan_rate_limiter.allow(client_key):
        raise HTTPException(status_code=429, detail="Too many scan requests, slow down")
    scan_id = db.create_scan(len(payload.targets) * len(payload.ports))
    asyncio.create_task(run_scan(payload.targets, payload.ports, payload.deep_chain, payload.analyze_vulns, scan_id))
    return {"scan_id": scan_id, "status": "started", "targets": len(payload.targets), "ports": payload.ports}


@app.get("/api/scan/{scan_id}", dependencies=[Depends(verify_token)])
async def get_scan(scan_id: int):
    data = db.get_scan_results(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return data


@app.get("/api/scans", dependencies=[Depends(verify_token)])
async def list_scans():
    return db.list_scans()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if not await verify_ws_token(websocket):
        await websocket.close(code=4401)
        return
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s: %s", request.url.path, type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def main():
    print(BANNER)
    if platform.system() != "Windows" and settings.port < 1024 and not _is_admin():
        logger.error(
            "Binding to port %s requires elevated privileges on this platform. "
            "Run with sudo, use setcap, or choose a port >= 1024.",
            settings.port,
        )
        sys.exit(1)
    import uvicorn
    try:
        uvicorn.run(
            "certgraph:app",
            host=settings.host,
            port=settings.port,
            log_level=settings.log_level.lower(),
            access_log=False,
            reload=False,
            workers=1,
        )
    except PermissionError:
        logger.error("Permission denied binding to %s:%s", settings.host, settings.port)
        sys.exit(1)
    except OSError as e:
        logger.error("Failed to start server: %s", type(e).__name__)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Shutdown requested")

if __name__ == "__main__":
    main()
