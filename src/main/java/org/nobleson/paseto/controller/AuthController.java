package org.nobleson.paseto.controller;


import dev.paseto.jpaseto.Paseto;
import dev.paseto.jpaseto.Pasetos;
import dev.paseto.jpaseto.lang.Keys;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.nobleson.paseto.data.AuthRequest;
import org.nobleson.paseto.data.AuthResponse;
import org.nobleson.paseto.data.RegistrationRequest;
import org.nobleson.paseto.service.AuthService;
import org.nobleson.paseto.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/paseto/user/auth")
@RequiredArgsConstructor

public class AuthController {


    private final AuthService authService;



    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest authRequest) {
        return new ResponseEntity<>(authService.authenticateUser(authRequest), HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegistrationRequest registrationRequest) {
        return new ResponseEntity<>(authService.registerUser(registrationRequest), HttpStatus.CREATED);
    }



//    public String register(@RequestBody RegistrationRequest request){
//
//        userService.save(request)
//
//    }

}
