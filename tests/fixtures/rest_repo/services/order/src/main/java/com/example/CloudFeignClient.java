package com.example;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@FeignClient(
    name = "customer-service",
    url = "${application.config.customer-url}"
)
public interface CloudFeignClient {

    @GetMapping("/{customer-id}")
    Customer getCustomer(@PathVariable("customer-id") String customerId);

    @PostMapping
    Customer createCustomer(Customer payload);
}
