package com.example.app;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class OrdinaryService {

    private final RestTemplate restTemplate;

    public OrdinaryService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    // Méthode ordinaire (pas de @KafkaListener) : ne doit pas être signalée
    // par la règle rest-call-in-kafka-listener.
    public String fetchOrder(String id) {
        return restTemplate.getForObject("http://order-service/orders/" + id, String.class);
    }
}
