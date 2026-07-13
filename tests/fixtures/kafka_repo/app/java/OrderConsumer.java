package com.example.app;

import org.springframework.kafka.annotation.KafkaListener;

public class OrderConsumer {

    @KafkaListener(topics = "orders.created")
    public void onOrderCreated(String payload) {
    }

    @KafkaListener(topics = "${app.kafka.topics.payments}")
    public void onPayment(String payload) {
    }

    @KafkaListener(topics = "${app.kafka.topics.unknown:orders.fallback}")
    public void onUnknownWithDefault(String payload) {
    }

    @KafkaListener(topics = "${app.kafka.topics.missing}")
    public void onMissingNoDefault(String payload) {
    }
}
