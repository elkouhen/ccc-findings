package com.example.app;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "payment-service")
public interface PaymentClient {

    @GetMapping("/payments/{id}")
    Payment getPayment(@PathVariable String id);

    @PostMapping("/payments")
    Payment createPayment(@RequestBody Payment payment);

    @RequestMapping(value = "/payments/{id}/cancel", method = RequestMethod.PUT)
    void cancelPayment(@PathVariable String id);
}
