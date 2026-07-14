package com.example.app;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

@Configuration
public class GatewayOrderConfiguration {

    @Bean
    public RouteLocator orderProxyRouting(RouteLocatorBuilder builder) {
        return builder.routes()
            .route(r -> r.path("/orders").and().method("POST").uri("http://order-service"))
            .route(r -> r.path("/orders").and().method("PUT").uri("http://order-service"))
            .route(r -> r.path("/orders/**").and().method("POST").uri("http://order-service"))
            .route(r -> r.path("/orders/**").and().method("PUT").uri("http://order-service"))
            .route(r -> r.path("/orders").and().method("GET").uri("http://order-history-service"))
            .build();
    }

    @Bean
    public RouterFunction<ServerResponse> orderHandlerRouting() {
        return RouterFunctions.route(GET("/orders/{orderId}"), request -> ServerResponse.ok().build());
    }
}
