package com.example.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;

public class ValueAnnotatedConsumer {

    @Value("${app.kafka.topics.orders}")
    private String ordersTopic;

    @Value("${app.kafka.topics.missing:orders.fallback}")
    private String fallbackTopic;

    @Value("${app.kafka.topics.unresolvable}")
    private String unresolvableTopic;

    private final KafkaTemplate<String, String> kafkaTemplate;

    public ValueAnnotatedConsumer(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @KafkaListener(topics = ordersTopic)
    public void onOrderCreated(String payload) {
    }

    public void publishFallback(String payload) {
        kafkaTemplate.send(fallbackTopic, payload);
    }

    public void publishUnresolvable(String payload) {
        kafkaTemplate.send(unresolvableTopic, payload);
    }
}
