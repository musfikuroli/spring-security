package com.musfikuroli.springsecurity.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    @GetMapping("/admin/hello")
    public String adminHello() {
        return "Hello, Admin!";
    }

    @GetMapping("/manager/hello")
    public String managerHello() {
        return "Hello, Manager!";
    }

    @GetMapping("/user/hello")
    public String userHello() {
        return "Hello, User!";
    }

    /**
     * Example of method-level security
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/onlyAdmin")
    public String onlyAdmin() {
        return "This is accessible only to ADMIN role";
    }
}
