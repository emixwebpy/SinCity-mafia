from extensions import db
from datetime import datetime, timedelta

class CityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)
    city = db.Column(db.String(100), nullable=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    description = db.Column(db.String(255))

    def is_active(self):
        return self.start_time <= datetime.utcnow() <= self.end_time