package com.example.z;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    @GetMapping("/z-status")
    public String status() {
        return "ok";
    }
}
