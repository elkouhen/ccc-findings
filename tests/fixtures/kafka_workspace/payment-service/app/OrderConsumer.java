package com.example.payment;

import org.springframework.kafka.annotation.KafkaListener;

public class OrderConsumer {

    @KafkaListener(topics = "orders.created")
    public void onOrderCreated(String payload) {
        // traite le paiement associé
    }
}
