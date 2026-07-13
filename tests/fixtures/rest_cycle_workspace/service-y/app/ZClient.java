package com.example.y;

import org.springframework.web.client.RestTemplate;

/** restTemplate configuré avec un rootUri pointant sur service-z. */
public class ZClient {

    private final RestTemplate restTemplate;

    public ZClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchZStatus() {
        return restTemplate.getForObject("/z-status", String.class);
    }
}
