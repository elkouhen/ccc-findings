package com.example.y;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    @GetMapping("/y-status")
    public String status() {
        return "ok";
    }
}
