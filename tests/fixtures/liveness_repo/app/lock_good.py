import threading

import requests

lock = threading.Lock()


def update_cache_good():
    response = requests.get("http://config-service/refresh", timeout=5)
    with lock:
        cache.update(response.json())
