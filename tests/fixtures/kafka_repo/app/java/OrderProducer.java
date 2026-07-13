package com.example.app;

import org.apache.kafka.clients.producer.ProducerRecord;
import org.springframework.kafka.core.KafkaTemplate;

public class OrderProducer {

    private final KafkaTemplate<String, String> kafkaTemplate;

    public OrderProducer(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void publishLiteral(String payload) {
        kafkaTemplate.send("orders.created", payload);
    }

    public void publishPlaceholder(String key, String payload) {
        kafkaTemplate.send("${app.kafka.topics.payments}", key, payload);
    }

    public void publishRecord(String payload) {
        var record = new ProducerRecord<String, String>("orders.updated", payload);
        kafkaTemplate.send(record);
    }

    public void publishDynamic(String topic, String payload) {
        kafkaTemplate.send(topic, payload);
    }
}
