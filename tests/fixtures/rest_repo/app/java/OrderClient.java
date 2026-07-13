package com.example.app;

import org.springframework.web.client.RestTemplate;

public class OrderClient {

    private final RestTemplate restTemplate;

    public OrderClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public Order fetchOrder(String id) {
        return restTemplate.getForObject("http://order-service/orders/" + id, Order.class);
    }

    public Order createOrder(Order order) {
        return restTemplate.postForObject("http://order-service/orders", order, Order.class);
    }

    public void updateOrder(String id, Order order) {
        restTemplate.put("http://order-service/orders/" + id, order);
    }

    public void deleteOrder(String id) {
        restTemplate.delete("http://order-service/orders/" + id);
    }

    public Order fetchOrderDynamicBase(String base, String id) {
        // URL construite dynamiquement (variable), pas littérale
        return restTemplate.getForObject(base + "/orders/" + id, Order.class);
    }
}
