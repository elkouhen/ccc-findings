package com.example.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;

import static org.springframework.kafka.support.KafkaHeaders.TOPIC;

public class MessageBuilderProducer {

    @Value("${app.kafka.topics.payments}")
    private String paymentsTopic;

    private final KafkaTemplate<String, String> kafkaTemplate;

    public MessageBuilderProducer(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void publishLiteral(String payload) {
        Message<String> message = MessageBuilder
                .withPayload(payload)
                .setHeader(TOPIC, "orders.confirmed")
                .build();
        kafkaTemplate.send(message);
    }

    public void publishValueAnnotated(String payload) {
        var message = MessageBuilder
                .withPayload(payload)
                .setHeader(TOPIC, paymentsTopic)
                .build();
        kafkaTemplate.send(message);
    }
}
