package com.project.streaming_auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
public class StreamingAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(StreamingAuthApplication.class, args);
    }
}