package com.example.x;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    @GetMapping("/x-status")
    public String status() {
        return "ok";
    }
}
