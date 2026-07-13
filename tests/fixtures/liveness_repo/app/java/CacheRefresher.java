package com.example.app;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class CacheRefresher {

    private final Object lock = new Object();
    private final RestTemplate restTemplate;
    private volatile String cache;

    public CacheRefresher(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void refreshBad() {
        synchronized (lock) {
            cache = restTemplate.getForObject("http://config-service/refresh", String.class);
        }
    }

    public void refreshGood() {
        String fresh = restTemplate.getForObject("http://config-service/refresh", String.class);
        synchronized (lock) {
            cache = fresh;
        }
    }
}
