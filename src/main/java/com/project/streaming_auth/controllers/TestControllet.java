import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

package com.project.streaming_auth.controllers;


@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping
    public String test() {
        return "Test successful!";
    }
}