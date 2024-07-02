package org.nobleson.paseto.service;


import lombok.RequiredArgsConstructor;
import org.nobleson.paseto.data.AuthResponse;
import org.nobleson.paseto.data.RegistrationRequest;
import org.nobleson.paseto.entities.AppUsers;
import org.nobleson.paseto.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;


    private final PasswordEncoder passwordEncoder;

    public AppUsers save(AppUsers user) {
        if(userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new RuntimeException("Username already exists");
        }

        return userRepository.save(user);
    }


}
