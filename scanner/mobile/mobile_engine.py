# scanner/mobile_engine.py

import os
import re
import json
import shutil
import logging
import zipfile
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

logging.basicConfig(level=logging.INFO)


# ─────────────────────────────────────────────────────────────
# ANDROID PERMISSION RISK DATABASE
# ─────────────────────────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    # Critical — direct privacy / security risk
    "android.permission.READ_CONTACTS":           "Critical",
    "android.permission.WRITE_CONTACTS":          "Critical",
    "android.permission.READ_CALL_LOG":           "Critical",
    "android.permission.WRITE_CALL_LOG":          "Critical",
    "android.permission.PROCESS_OUTGOING_CALLS":  "Critical",
    "android.permission.READ_SMS":                "Critical",
    "android.permission.RECEIVE_SMS":             "Critical",
    "android.permission.SEND_SMS":                "Critical",
    "android.permission.RECORD_AUDIO":            "Critical",
    "android.permission.CAMERA":                  "High",
    "android.permission.ACCESS_FINE_LOCATION":    "High",
    "android.permission.ACCESS_COARSE_LOCATION":  "Medium",
    "android.permission.READ_EXTERNAL_STORAGE":   "Medium",
    "android.permission.WRITE_EXTERNAL_STORAGE":  "Medium",
    "android.permission.GET_ACCOUNTS":            "Medium",
    "android.permission.USE_BIOMETRIC":           "Medium",
    "android.permission.USE_FINGERPRINT":         "Medium",
    # High risk system permissions
    "android.permission.INSTALL_PACKAGES":        "Critical",
    "android.permission.DELETE_PACKAGES":         "Critical",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": "High",
    "android.permission.MASTER_CLEAR":            "Critical",
    "android.permission.FACTORY_RESET":           "Critical",
    "android.permission.BIND_DEVICE_ADMIN":       "Critical",
}

# ─────────────────────────────────────────────────────────────
# SECRET PATTERNS  (mobile-specific + inherited from sast_engine)
# ─────────────────────────────────────────────────────────────
SECRET_PATTERNS = {
    # Cloud & infrastructure
    "AWS Access Key":          r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":          r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":          r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Client ID":  r"[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com",
    "Firebase URL":            r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase API Key":        r"AIza[0-9A-Za-z\-_]{35}",
    # Mobile-specific
    "Google Maps Key":         r"AIza[0-9A-Za-z\-_]{35}",
    "Facebook App ID":         r"(?i)facebook.{0,10}app.{0,10}id.{0,10}['\"][0-9]{10,20}['\"]",
    "Facebook App Secret":     r"(?i)facebook.{0,10}(secret|token).{0,10}['\"][0-9a-f]{32}['\"]",
    "Twitter API Key":         r"(?i)twitter.{0,10}(api_key|consumer_key).{0,10}['\"][a-zA-Z0-9]{25,}['\"]",
    "Stripe Key":              r"sk_(live|test)_[0-9a-zA-Z]{24,}",
    "SendGrid API Key":        r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}",
    # Generic secrets
    "Hardcoded Password":      r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    "Hardcoded Secret/Token":  r"(?i)(secret|auth_token|api_key|apikey|access_token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Private Key Block":       r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Database Connection":     r"(mongodb\+srv|postgres|mysql|sqlite)://[^\s\"'<>]+",
    "Hardcoded IP Address":    r"\b(?!10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "JWT Secret":              r"(?i)jwt.{0,15}secret.{0,15}['\"][^'\"]{8,}['\"]",
}

# ─────────────────────────────────────────────────────────────
# DANGEROUS CODE PATTERNS  (Java / Kotlin / Smali)
# ─────────────────────────────────────────────────────────────
DANGEROUS_CODE = {
    # Crypto weaknesses
    "Weak Crypto - MD5":               r"MessageDigest\.getInstance\([\"']MD5[\"']\)",
    "Weak Crypto - SHA1":              r"MessageDigest\.getInstance\([\"']SHA-?1[\"']\)",
    "Weak Cipher - DES":               r"Cipher\.getInstance\([\"']DES[\"']",
    "Weak Cipher - ECB Mode":          r"Cipher\.getInstance\([\"'][^\"']*\/ECB\/",
    "Weak Random":                     r"\bnew Random\(\)",

    # Insecure storage
    "Cleartext SharedPreferences":     r"getSharedPreferences\(",
    "World Readable File":             r"MODE_WORLD_READABLE",
    "World Writeable File":            r"MODE_WORLD_WRITEABLE",
    "External Storage Write":          r"getExternalStorageDirectory\(\)",

    # Network security
    "Cleartext HTTP Traffic":          r"http://(?!localhost|127\.0\.0\.1)[a-zA-Z0-9]",
    "TrustAll SSL Manager":            r"TrustAllCerts|X509TrustManager|checkServerTrusted",
    "Hostname Verifier Disabled":      r"ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier",
    "SSL Error Ignored":               r"onReceivedSslError.*proceed\(\)",

    # Code execution
    "Dynamic Code Loading":            r"DexClassLoader|PathClassLoader|loadDex",
    "JavaScript Enabled in WebView":   r"setJavaScriptEnabled\(true\)",
    "JavaScript Interface Exposed":    r"addJavascriptInterface\(",
    "Runtime Command Execution":       r"Runtime\.getRuntime\(\)\.exec\(",
    "Reflection Usage":                r"java\.lang\.reflect\.",

    # Data leakage
    "Log Sensitive Data":              r"Log\.(d|v|i|e|w)\s*\(.*(password|token|secret|key|auth)",
    "Clipboard Sensitive":             r"ClipboardManager",

    # Intent vulnerabilities
    "Implicit Intent":                 r"new Intent\(\s*['\"][a-zA-Z.]+['\"]",
    "Exported Activity No Permission": r"android:exported=['\"]true['\"]",
}

# File extensions to scan for code patterns
SCANNABLE_EXTENSIONS = {
    ".java", ".kt", ".xml", ".json", ".js",
    ".smali", ".properties", ".gradle", ".yaml", ".yml"
}

# Extensions to skip entirely
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".mp3", ".mp4", ".ogg", ".ttf", ".otf",
    ".dex", ".so", ".class"
}


class MobileEngine:

    def __init__(self, extract_base="temp_apk"):
        self.extract_base = extract_base

    # ─────────────────────────────────────────
    # MAIN ENTRY POINT
    # ─────────────────────────────────────────
    def scan(self, apk_path):
        """
        Full APK analysis pipeline.

        apk_path : path to the uploaded .apk file
        Returns  : list of finding dicts compatible with
                   AIReportGenerator / RiskPrioritizer
        """
        findings = []
        apk_name = Path(apk_path).stem
        extract_dir = os.path.join(self.extract_base, apk_name)

        logging.info(f"[MOBILE] Starting scan: {apk_path}")

        # ── 1. Decompile with apktool ─────────────────
        decompiled_dir = self._decompile(apk_path, extract_dir)

        # ── 2. Raw ZIP extraction (fallback / supplement)
        zip_dir = extract_dir + "_zip"
        self._extract_zip(apk_path, zip_dir)

        # ── 3. Manifest analysis ──────────────────────
        manifest_path = os.path.join(
            decompiled_dir or zip_dir,
            "AndroidManifest.xml"
        )
        if os.path.exists(manifest_path):
            findings.extend(self._analyze_manifest(manifest_path, apk_name))
        else:
            logging.warning("[MOBILE] AndroidManifest.xml not found")

        # ── 4. Secret scanning ────────────────────────
        scan_root = decompiled_dir or zip_dir
        if scan_root and os.path.exists(scan_root):
            findings.extend(self._scan_secrets(scan_root, apk_name))
            findings.extend(self._scan_dangerous_code(scan_root, apk_name))
            findings.extend(self._check_network_security_config(scan_root, apk_name))
            findings.extend(self._check_backup_flag(scan_root, apk_name))

        # ── 5. Cleanup ────────────────────────────────
        self._cleanup([extract_dir, zip_dir])

        logging.info(f"[MOBILE] Scan complete. {len(findings)} findings.")
        return findings

    # ─────────────────────────────────────────
    # DECOMPILE WITH APKTOOL
    # ─────────────────────────────────────────
    def _decompile(self, apk_path, output_dir):
        """
        Attempt decompilation using apktool.
        Returns output directory on success, None on failure.
        apktool must be installed: https://apktool.org
        """
        try:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)

            result = subprocess.run(
                ["apktool", "d", apk_path, "-o", output_dir, "--force"],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0 and os.path.exists(output_dir):
                logging.info(f"[MOBILE] apktool decompiled to {output_dir}")
                return output_dir
            else:
                logging.warning(f"[MOBILE] apktool failed: {result.stderr[:200]}")
                return None

        except FileNotFoundError:
            logging.warning("[MOBILE] apktool not found. Falling back to ZIP extraction.")
            return None
        except subprocess.TimeoutExpired:
            logging.error("[MOBILE] apktool timed out.")
            return None
        except Exception as e:
            logging.error(f"[MOBILE] Decompile error: {e}")
            return None

    # ─────────────────────────────────────────
    # ZIP EXTRACTION (FALLBACK)
    # ─────────────────────────────────────────
    def _extract_zip(self, apk_path, output_dir):
        """APKs are ZIP files. Extract raw contents as fallback."""
        try:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            os.makedirs(output_dir, exist_ok=True)

            with zipfile.ZipFile(apk_path, "r") as zf:
                zf.extractall(output_dir)

            logging.info(f"[MOBILE] ZIP extracted to {output_dir}")
        except Exception as e:
            logging.error(f"[MOBILE] ZIP extraction failed: {e}")

    # ─────────────────────────────────────────
    # MANIFEST ANALYSIS
    # ─────────────────────────────────────────
    def _analyze_manifest(self, manifest_path, apk_name):
        findings = []

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            ns = {"android": "http://schemas.android.com/apk/res/android"}

            # ── Package name ──────────────────────────
            package = root.get("package", "unknown")

            # ── debuggable flag ───────────────────────
            app_el = root.find("application")
            if app_el is not None:
                debuggable = app_el.get(
                    "{http://schemas.android.com/apk/res/android}debuggable", "false"
                )
                if debuggable.lower() == "true":
                    findings.append(self._finding(
                        ftype="Debug Mode Enabled",
                        severity="High",
                        file="AndroidManifest.xml",
                        apk=apk_name,
                        desc="App is built with android:debuggable=true. Attackers can attach "
                             "a debugger, inspect memory, and extract secrets at runtime.",
                        evidence="android:debuggable=\"true\""
                    ))

                # ── allowBackup flag ──────────────────
                allow_backup = app_el.get(
                    "{http://schemas.android.com/apk/res/android}allowBackup", "true"
                )
                if allow_backup.lower() != "false":
                    findings.append(self._finding(
                        ftype="Insecure Backup Allowed",
                        severity="Medium",
                        file="AndroidManifest.xml",
                        apk=apk_name,
                        desc="android:allowBackup is not explicitly set to false. App data can "
                             "be extracted via ADB backup without root on unencrypted devices.",
                        evidence="android:allowBackup not set to false"
                    ))

                # ── cleartext traffic ─────────────────
                cleartext = app_el.get(
                    "{http://schemas.android.com/apk/res/android}usesCleartextTraffic", "false"
                )
                if cleartext.lower() == "true":
                    findings.append(self._finding(
                        ftype="Cleartext Traffic Permitted",
                        severity="High",
                        file="AndroidManifest.xml",
                        apk=apk_name,
                        desc="android:usesCleartextTraffic=true allows unencrypted HTTP. "
                             "Credentials and data are exposed to network interception.",
                        evidence="android:usesCleartextTraffic=\"true\""
                    ))

            # ── Permissions ───────────────────────────
            for perm in root.findall("uses-permission"):
                name = perm.get(
                    "{http://schemas.android.com/apk/res/android}name", ""
                )
                severity = DANGEROUS_PERMISSIONS.get(name)
                if severity:
                    findings.append(self._finding(
                        ftype="Dangerous Permission",
                        severity=severity,
                        file="AndroidManifest.xml",
                        apk=apk_name,
                        desc=f"App requests sensitive permission: {name}",
                        evidence=name
                    ))

            # ── Exported components ───────────────────
            for tag in ["activity", "service", "receiver", "provider"]:
                for el in root.iter(tag):
                    exported = el.get(
                        "{http://schemas.android.com/apk/res/android}exported", ""
                    )
                    name = el.get(
                        "{http://schemas.android.com/apk/res/android}name", tag
                    )
                    permission = el.get(
                        "{http://schemas.android.com/apk/res/android}permission", ""
                    )

                    if exported.lower() == "true" and not permission:
                        findings.append(self._finding(
                            ftype=f"Unprotected Exported {tag.capitalize()}",
                            severity="High",
                            file="AndroidManifest.xml",
                            apk=apk_name,
                            desc=f"Component '{name}' is exported with no permission "
                                 f"restriction. Any app can interact with it.",
                            evidence=f"android:exported=true on <{tag}> {name}"
                        ))

        except ET.ParseError as e:
            logging.warning(f"[MOBILE] Could not parse manifest: {e}")
        except Exception as e:
            logging.error(f"[MOBILE] Manifest analysis error: {e}")

        return findings

    # ─────────────────────────────────────────
    # SECRET SCANNING
    # ─────────────────────────────────────────
    def _scan_secrets(self, root_dir, apk_name):
        findings = []

        for filepath in self._walk_files(root_dir):
            try:
                content = Path(filepath).read_text(errors="ignore")
                rel_path = os.path.relpath(filepath, root_dir)

                for secret_name, pattern in SECRET_PATTERNS.items():
                    for match in re.finditer(pattern, content):
                        evidence = match.group(0)[:80]

                        # Skip obvious placeholders
                        if any(p in evidence.lower() for p in
                               ["example", "your_key", "xxxxx", "placeholder", "dummy"]):
                            continue

                        findings.append(self._finding(
                            ftype="Hardcoded Secret",
                            severity="Critical",
                            file=rel_path,
                            apk=apk_name,
                            desc=f"Potential {secret_name} found hardcoded in source. "
                                 f"Secrets in APKs can be extracted by anyone who downloads the app.",
                            evidence=evidence
                        ))

            except Exception as e:
                logging.debug(f"[MOBILE] Could not read {filepath}: {e}")

        return findings

    # ─────────────────────────────────────────
    # DANGEROUS CODE PATTERNS
    # ─────────────────────────────────────────
    def _scan_dangerous_code(self, root_dir, apk_name):
        findings = []

        for filepath in self._walk_files(root_dir):
            ext = Path(filepath).suffix.lower()
            if ext not in {".java", ".kt", ".smali", ".js"}:
                continue

            try:
                content = Path(filepath).read_text(errors="ignore")
                rel_path = os.path.relpath(filepath, root_dir)

                for vuln_name, pattern in DANGEROUS_CODE.items():
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        # Determine severity from pattern category
                        severity = self._code_severity(vuln_name)
                        findings.append(self._finding(
                            ftype="Insecure Code Pattern",
                            severity=severity,
                            file=rel_path,
                            apk=apk_name,
                            desc=f"{vuln_name} detected. {self._code_advice(vuln_name)}",
                            evidence=match.group(0)[:100]
                        ))

            except Exception as e:
                logging.debug(f"[MOBILE] Could not scan {filepath}: {e}")

        return findings

    # ─────────────────────────────────────────
    # NETWORK SECURITY CONFIG CHECK
    # ─────────────────────────────────────────
    def _check_network_security_config(self, root_dir, apk_name):
        """
        Check res/xml/network_security_config.xml for
        cleartext domains or user-cert trust.
        """
        findings = []
        config_paths = [
            os.path.join(root_dir, "res", "xml", "network_security_config.xml"),
            os.path.join(root_dir, "res", "xml", "network_config.xml"),
        ]

        for config_path in config_paths:
            if not os.path.exists(config_path):
                continue

            try:
                content = Path(config_path).read_text(errors="ignore")

                if "cleartextTrafficPermitted=\"true\"" in content:
                    findings.append(self._finding(
                        ftype="Network Security Config: Cleartext Allowed",
                        severity="High",
                        file="res/xml/network_security_config.xml",
                        apk=apk_name,
                        desc="Network security config explicitly permits cleartext (HTTP) traffic "
                             "for one or more domains.",
                        evidence="cleartextTrafficPermitted=\"true\""
                    ))

                if "<certificates src=\"user\"" in content:
                    findings.append(self._finding(
                        ftype="Network Security Config: User Certs Trusted",
                        severity="High",
                        file="res/xml/network_security_config.xml",
                        apk=apk_name,
                        desc="App trusts user-installed certificates. This weakens SSL pinning "
                             "and enables trivial MITM attacks on rooted devices.",
                        evidence="<certificates src=\"user\""
                    ))

            except Exception as e:
                logging.debug(f"[MOBILE] NSC read error: {e}")

        return findings

    # ─────────────────────────────────────────
    # BACKUP FLAG DOUBLE-CHECK
    # ─────────────────────────────────────────
    def _check_backup_flag(self, root_dir, apk_name):
        """
        Check gradle/build files for backup rules
        that might override manifest settings.
        """
        findings = []
        gradle_path = os.path.join(root_dir, "build.gradle")

        if os.path.exists(gradle_path):
            try:
                content = Path(gradle_path).read_text(errors="ignore")
                if "minSdkVersion" in content:
                    match = re.search(r"minSdkVersion\s+(\d+)", content)
                    if match:
                        min_sdk = int(match.group(1))
                        if min_sdk < 18:
                            findings.append(self._finding(
                                ftype="Low Minimum SDK Version",
                                severity="Medium",
                                file="build.gradle",
                                apk=apk_name,
                                desc=f"minSdkVersion is {min_sdk}. Devices below API 18 lack "
                                     f"full disk encryption and many security improvements.",
                                evidence=f"minSdkVersion {min_sdk}"
                            ))
            except Exception as e:
                logging.debug(f"[MOBILE] Gradle read error: {e}")

        return findings

    # ─────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────
    def _walk_files(self, root_dir):
        """Yield all scannable file paths under root_dir."""
        for dirpath, _, filenames in os.walk(root_dir):
            for fname in filenames:
                ext = Path(fname).suffix.lower()
                if ext in SKIP_EXTENSIONS:
                    continue
                yield os.path.join(dirpath, fname)

    def _code_severity(self, vuln_name):
        critical = {"TrustAll SSL Manager", "Hostname Verifier Disabled",
                    "SSL Error Ignored", "Dynamic Code Loading",
                    "JavaScript Interface Exposed", "Runtime Command Execution"}
        high = {"Weak Crypto - MD5", "Weak Cipher - DES", "Weak Cipher - ECB Mode",
                "Cleartext HTTP Traffic", "JavaScript Enabled in WebView",
                "World Readable File", "World Writeable File",
                "Log Sensitive Data"}
        if vuln_name in critical:
            return "Critical"
        if vuln_name in high:
            return "High"
        return "Medium"

    def _code_advice(self, vuln_name):
        advice = {
            "Weak Crypto - MD5":               "Use SHA-256 or SHA-3 instead.",
            "Weak Cipher - ECB Mode":          "Use AES/GCM or AES/CBC with a random IV.",
            "Weak Random":                     "Use SecureRandom() for all security-sensitive randomness.",
            "TrustAll SSL Manager":            "Implement a proper X509TrustManager that validates the certificate chain.",
            "Hostname Verifier Disabled":      "Remove ALLOW_ALL_HOSTNAME_VERIFIER and validate hostnames properly.",
            "SSL Error Ignored":               "Do not call handler.proceed() on SSL errors.",
            "JavaScript Enabled in WebView":   "Only enable JS in WebViews if absolutely necessary; use setAllowFileAccess(false).",
            "JavaScript Interface Exposed":    "Exposed JS interfaces allow XSS in the WebView to call native Java code.",
            "Dynamic Code Loading":            "Loading code at runtime from external sources enables code injection attacks.",
            "Log Sensitive Data":              "Remove Log statements that print credentials, tokens, or PII.",
            "Cleartext HTTP Traffic":          "Use HTTPS for all network communication.",
            "External Storage Write":          "Avoid writing sensitive data to external storage; use internal storage with MODE_PRIVATE.",
        }
        return advice.get(vuln_name, "Review this usage carefully before shipping to production.")

    def _finding(self, ftype, severity, file, apk, desc, evidence=""):
        return {
            "type":        ftype,
            "severity":    severity,
            "url":         f"apk://{apk}/{file}",
            "file":        file,
            "apk":         apk,
            "description": desc,
            "evidence":    evidence,
            "confidence":  0.85,
        }

    def _cleanup(self, dirs):
        for d in dirs:
            if d and os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)