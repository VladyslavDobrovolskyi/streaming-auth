package com.project.streaming_auth.requests;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Past;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
public class RegistryUserRequest {

    @NotBlank(message = "Name is required")
    private String username;

    @NotBlank(message = "Password is required")
    private String password;
}
