from kafka import KafkaConsumer

consumer = KafkaConsumer("orders")
for message in consumer:
    process(message)


def batch_job(users):
    # boucle for ordinaire, sans lien avec un consumer Kafka : ne doit pas
    # être signalée par la règle consumer-loop.
    import requests

    for user in users:
        requests.get(f"http://user-service/{user}", timeout=5)
