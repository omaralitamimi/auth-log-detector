import unittest
from main import detect


class DetectionTests(unittest.TestCase):
    def test_alerts_at_threshold(self):
        events = [{"timestamp": f"2026-01-01T00:0{i}:00Z", "username": "alex", "source_ip": "203.0.113.5", "result": "failure"} for i in range(5)]
        self.assertEqual(detect(events)[0]["failures"], 5)

    def test_success_is_ignored(self):
        self.assertEqual(detect([{"timestamp": "2026-01-01T00:00:00Z", "username": "a", "source_ip": "1.1.1.1", "result": "success"}], 1), [])


if __name__ == "__main__":
    unittest.main()
