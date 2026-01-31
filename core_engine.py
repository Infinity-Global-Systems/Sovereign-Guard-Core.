import os
import hashlib
import datetime

class SovereignGuard:
    """
    Sovereign-Guard-Core: Advanced Infrastructure Integrity Monitor.
    Designed for high-availability enterprise environments.
    """
    def __init__(self, monitored_directory):
        self.monitored_directory = monitored_directory
        self.integrity_log = "guard_log.txt"
        self.fingerprints = {}

    def generate_fingerprint(self, file_path):
        """توليد بصمة رقمية مشفرة للملفات الحساسة"""
        hash_func = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_func.update(byte_block)
        return hash_func.hexdigest()

    def audit_infrastructure(self):
        """فحص سلامة النظام واكتشاف أي اختراق أو تعديل غير مصرح به"""
        print(f"🛡️ [AUDIT STARTED] {datetime.datetime.now()}")
        for root, _, files in os.walk(self.monitored_directory):
            for file in files:
                full_path = os.path.join(root, file)
                current_hash = self.generate_fingerprint(full_path)
                
                if full_path in self.fingerprints:
                    if self.fingerprints[full_path] != current_hash:
                        self.alert_breach(full_path)
                else:
                    self.fingerprints[full_path] = current_hash
        print(f"✅ [AUDIT COMPLETE] System is Secure & Sovereign.")

    def alert_breach(self, file_path):
        """تنبيه فوري في حال حدوث تعديل مشبوه"""
        msg = f"⚠️ [SECURITY ALERT] Unauthorized modification detected in: {file_path}"
        print(msg)
        with open(self.integrity_log, "a") as log:
            log.write(f"{datetime.datetime.now()} - {msg}\n")

if __name__ == "__main__":
    # تشغيل النظام على ملفات التكوين الحساسة
    guard = SovereignGuard(monitored_directory="./config")
    guard.audit_infrastructure()
