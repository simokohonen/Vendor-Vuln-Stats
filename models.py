# models.py

from extensions import db

class Vendor(db.Model):
    __tablename__ = 'vendors'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    cve_count = db.Column(db.Integer, default=0, nullable=False)
    cisa_kev_count = db.Column(db.Integer, default=0, nullable=False)
    ransomware_count = db.Column(db.Integer, default=0, nullable=False)
    danger_score = db.Column(db.Float, default=0.0, nullable=False)

    def __repr__(self):
        return (f"<Vendor {self.name}: CVE={self.cve_count}, "
                f"CISA KEV={self.cisa_kev_count}, Ransomware={self.ransomware_count}, "
                f"Danger Score={self.danger_score}>")
