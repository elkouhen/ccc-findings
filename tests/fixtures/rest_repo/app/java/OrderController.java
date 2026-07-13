package com.example.app;

import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {

    @GetMapping("/orders/{id}")
    public Order getOrder(@PathVariable String id) {
        return null;
    }

    @PostMapping("/orders")
    public Order createOrder(@RequestBody Order order) {
        return null;
    }

    @PutMapping("/orders/{id}")
    public Order updateOrder(@PathVariable String id, @RequestBody Order order) {
        return null;
    }

    @DeleteMapping("/orders/{id}")
    public void deleteOrder(@PathVariable String id) {
    }

    @PatchMapping("/orders/{id}/status")
    public Order patchStatus(@PathVariable String id) {
        return null;
    }

    @RequestMapping(value = "/orders/{id}/summary", method = RequestMethod.GET)
    public Order getSummary(@PathVariable String id) {
        return null;
    }
}
