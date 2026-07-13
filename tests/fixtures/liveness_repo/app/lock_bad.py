import threading

import requests

lock = threading.Lock()


def update_cache_bad():
    with lock:
        requests.get("http://config-service/refresh")
