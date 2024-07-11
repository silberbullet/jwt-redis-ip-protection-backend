package com.develop.backend;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PingController {
    @PostMapping("/ping")
    public String ping() {
        return "Hello Spring Security";
    }
}
