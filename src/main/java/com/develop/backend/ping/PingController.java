package com.develop.backend.ping;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;

@RestController
@RequestMapping("/api")
public class PingController {

    @PostMapping("/ping")
    public String getHello() {
        return "Hello Spring Security!";
    }

}
