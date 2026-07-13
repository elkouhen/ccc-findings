package com.example.app;

import org.springframework.web.reactive.function.client.WebClient;

public class WebClientCaller {

    private final WebClient webClient;

    public WebClientCaller(WebClient webClient) {
        this.webClient = webClient;
    }

    public void fetch(String id) {
        webClient.get().uri("/orders/{id}", id).retrieve();
    }

    public void create() {
        webClient.post().uri("/orders").retrieve();
    }
}
