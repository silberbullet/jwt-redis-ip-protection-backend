package com.develop.backend.api.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.develop.backend.api.req.PingReq;

@RestController
public class PingController {
    @PostMapping("/ping")
    public String ping(PingReq pingReq) {

        return "Hello Spring Security!! I'm " + pingReq.getUserId() + " and " + pingReq.getUserIp();
    }
}
