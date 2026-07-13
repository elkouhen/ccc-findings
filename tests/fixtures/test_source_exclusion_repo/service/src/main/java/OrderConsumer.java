package com.example.app;

import org.springframework.kafka.annotation.KafkaListener;

public class OrderConsumer {

    @KafkaListener(topics = "orders.created")
    public void onOrderCreated(String payload) {
        System.out.println("processing order");
    }
}
