package com.nduyhai.keycloak.bridge.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
class HomeController {
    @GetMapping("/")
    @ResponseBody
    String home() { return "OK"; }
}