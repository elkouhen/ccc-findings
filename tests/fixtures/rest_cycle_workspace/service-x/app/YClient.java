package com.example.x;

import org.springframework.web.client.RestTemplate;

/**
 * restTemplate est configuré avec un rootUri pointant sur service-y
 * (RestTemplateBuilder.rootUri(...)) ; les appels ne portent donc que le
 * chemin, pas l'hôte.
 */
public class YClient {

    public String fetchYStatus() {
        return new RestTemplate().getForObject("/y-status", String.class);
    }
}
