import datetime

class Alerting:
    def __init__(self):
        # In future, this could initialize frames and involve counter.
        pass

    def generate_alert(self, alert_type, details):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[ALERT - {alert_type}] @ {timestamp}")
        print(f"Details: {details}")
        print("-" * 50)

   # def counter_record(self)


   # def frames_alert(self)
