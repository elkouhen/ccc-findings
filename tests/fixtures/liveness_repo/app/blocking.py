import threading
from concurrent.futures import ThreadPoolExecutor


def wait_bad(t: threading.Thread):
    t.join()


def wait_good(t: threading.Thread):
    t.join(timeout=10)


def fetch_bad(executor: ThreadPoolExecutor, fn):
    future = executor.submit(fn)
    return future.result()


def fetch_good(executor: ThreadPoolExecutor, fn):
    future = executor.submit(fn)
    return future.result(timeout=10)
