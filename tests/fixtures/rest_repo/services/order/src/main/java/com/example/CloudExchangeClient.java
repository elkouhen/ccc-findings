package com.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.List;

public class CloudExchangeClient {

    @Value("${application.config.product-url}")
    private String productUrl;

    private final RestTemplate restTemplate;

    public CloudExchangeClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public ResponseEntity<List<String>> purchase(List<String> body) {
        return restTemplate.exchange(
            productUrl + "/purchase",
            HttpMethod.POST,
            new HttpEntity<>(body),
            new ParameterizedTypeReference<>() {
            }
        );
    }
}
