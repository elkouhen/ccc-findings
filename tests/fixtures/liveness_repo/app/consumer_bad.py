import requests
from kafka import KafkaConsumer

consumer = KafkaConsumer("orders")
for message in consumer:
    requests.get("http://payment-service/charge")
