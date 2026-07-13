import requests


def fetch_order(order_id):
    return requests.get(f"http://order-service/orders/{order_id}")


def create_order(payload):
    return requests.post("http://order-service/orders", json=payload)


def update_order(order_id, payload):
    return requests.put("http://order-service/orders/" + order_id, json=payload)


def delete_order(order_id):
    return requests.delete("http://order-service/orders/" + order_id)


def patch_status(order_id, payload):
    return requests.patch(f"http://order-service/orders/{order_id}/status", json=payload)


def fetch_order_dynamic(base_url, order_id):
    # URL entièrement dynamique (variable), aucun littéral exploitable
    return requests.get(base_url)
