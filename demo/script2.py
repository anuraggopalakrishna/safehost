import requests
import time
import random

# Replace with your server's IP and port
TARGET_URL = "http://127.0.0.1:5000"

# Simulated debug data to show all 3 prediction levels
DEBUG_PAYLOADS = [
    {"label": "Benign", "confidence": 0},
    {"label": "Benign", "confidence": 0},
    {"label": "Benign", "confidence": 0},
    {"label": "Benign", "confidence": 0.38},
    {"label": "Benign", "confidence": 0.278},
]


def simulate_normal_traffic():
    count = 0
    while True:
        try:
            if count % 5 == 0:
                # Every 5th request sends debug label + confidence
                payload = random.choice(DEBUG_PAYLOADS)
                print(
                    f"Sending debug traffic with label={payload['label']} and confidence={payload['confidence']}"
                )
                requests.get(TARGET_URL, params=payload)
            else:
                print("Sending normal request")
                requests.get(TARGET_URL)

        except Exception as e:
            print(f"Error sending request: {e}")

        time.sleep(random.uniform(1, 3))
        count += 1


if __name__ == "__main__":
    simulate_normal_traffic()
