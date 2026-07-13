package com.example.app;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class OrderConsumer {

    private final RestTemplate restTemplate;

    public OrderConsumer(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @KafkaListener(topics = "orders.created")
    public void onOrderCreatedBad(String payload) {
        restTemplate.postForObject("http://payment-service/charge", payload, String.class);
    }

    @KafkaListener(topics = "orders.created")
    public void onOrderCreatedGood(String payload) {
        publishToOutbox(payload);
    }

    private void publishToOutbox(String payload) {
        // écrit en base pour traitement asynchrone, pas d'appel réseau ici
    }
}
