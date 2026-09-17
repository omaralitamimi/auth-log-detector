# Authentication Log Detector

Small SOC-oriented Python project that detects repeated failed sign-ins by username and source IP inside a rolling time window. The included data is synthetic and safe for offline analysis.

## Run

```bash
python main.py sample_auth.jsonl
python -m unittest -v
```

## Skills demonstrated

- JSONL log parsing and UTC timestamp handling
- Sliding-window detection logic
- Clear, machine-readable alerts
- Unit testing with the Python standard library

This project creates investigation leads; it does not claim that an alert proves malicious activity.
