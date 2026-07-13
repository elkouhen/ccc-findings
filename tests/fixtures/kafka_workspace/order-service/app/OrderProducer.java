package com.example.order;

import org.springframework.kafka.core.KafkaTemplate;

public class OrderProducer {

    private final KafkaTemplate<String, String> kafkaTemplate;

    public OrderProducer(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void publishOrderCreated(String payload) {
        kafkaTemplate.send("orders.created", payload);
    }
}
