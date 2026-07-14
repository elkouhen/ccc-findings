package com.example.app;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConsumerConfiguration {

    @Bean
    public RouteLocator consumerProxyRouting(RouteLocatorBuilder builder) {
        return builder.routes()
            .route(r -> r.path("/consumers").and().method("POST").uri("http://consumer-service"))
            .route(r -> r.path("/consumers").and().method("PUT").uri("http://consumer-service"))
            .build();
    }
}
