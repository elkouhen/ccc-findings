package com.example.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.List;

import static org.springframework.http.HttpMethod.POST;

public class ExchangeClient {

    @Value("${application.config.product-url}")
    private String productUrl;

    private final RestTemplate restTemplate;

    public ExchangeClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public ResponseEntity<List<String>> purchase(List<String> body) {
        return restTemplate.exchange(
            productUrl + "/purchase",
            POST,
            new HttpEntity<>(body),
            new ParameterizedTypeReference<>() {
            }
        );
    }

    public ResponseEntity<String> fetchOne(String id) {
        return restTemplate.exchange(
            "http://catalog-service/api/v1/products/" + id,
            HttpMethod.GET,
            null,
            String.class
        );
    }
}
