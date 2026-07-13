import requests


def call_payment_bad():
    return requests.get("http://payment-service/charge")


def call_payment_good():
    return requests.get("http://payment-service/charge", timeout=5)


def post_order_bad(payload):
    return requests.post("http://order-service/orders", json=payload)


def post_order_good(payload):
    return requests.post("http://order-service/orders", json=payload, timeout=(3, 5))
