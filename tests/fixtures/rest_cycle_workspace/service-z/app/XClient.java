package com.example.z;

import org.springframework.web.client.RestTemplate;

/** restTemplate configuré avec un rootUri pointant sur service-x. */
public class XClient {

    private final RestTemplate restTemplate;

    public XClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchXStatus() {
        return restTemplate.getForObject("/x-status", String.class);
    }
}
