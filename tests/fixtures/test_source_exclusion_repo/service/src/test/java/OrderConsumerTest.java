package com.example.app;

import org.springframework.kafka.annotation.KafkaListener;

public class OrderConsumerTest {

    @KafkaListener(topics = "orders.created")
    public void onOrderCreatedInTest(String payload) {
        System.out.println("processing order in a test");
    }
}
