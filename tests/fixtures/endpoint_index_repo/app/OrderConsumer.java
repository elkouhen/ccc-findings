package com.example.app;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.web.client.RestTemplate;

public class OrderConsumer {

    private final RestTemplate restTemplate;

    public OrderConsumer(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @KafkaListener(topics = "orders.created")
    public void onOrderCreated(String payload) {
        System.out.println("processing order");
        restTemplate.postForObject("http://payment-service/charge", payload, String.class);
    }
}
