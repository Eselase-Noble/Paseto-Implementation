package org.nobleson.paseto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.nobleson.paseto.data.AuthRequest;
import org.nobleson.paseto.data.AuthResponse;
import org.nobleson.paseto.data.RegistrationRequest;
import org.nobleson.paseto.entities.AppUsers;
import org.nobleson.paseto.entities.Token;
import org.nobleson.paseto.enums.TokenType;
import org.nobleson.paseto.repository.TokenRepository;
import org.nobleson.paseto.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final UserService userService;
    private final PasetoService pasetoService;
    private final TokenRepository tokenRepository;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;


    public AuthResponse registerUser(RegistrationRequest request){
        var user = AppUsers.builder()
                .userID(request.getUserID())
                .surname(request.getSurname())
                .otherNames(request.getOtherName())
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .phone(request.getPhone())
                .role(request.getRole())
                .build();

        var savedUser = userService.save(user);
        var token = pasetoService.generateToken(user);
        var refreshToken = pasetoService.generateRefreshToken(user);
        saveUserToken(savedUser, token);

        return AuthResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken)
                .build();
    }


    public AuthResponse authenticateUser(AuthRequest request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword())
        );

        var user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        var pasetoToken = pasetoService.generateToken(user);
        var refreshToken = pasetoService.generateRefreshToken(user);
        revokeAllUserToken(user);
        saveUserToken(user, pasetoToken);

        return AuthResponse
                .builder()
                .accessToken(pasetoToken)
                .refreshToken(refreshToken)
                .build();
    }


    public void saveUserToken(AppUsers user, String pasetoToken){
    var token = Token.builder()
            .user(user)
            .token(pasetoToken)
            .tokenType(TokenType.BEARER)
            .expired(false)
            .revoked(false)
            .build();

    tokenRepository.save(token);
    }

    /**
     * This method is used to revoke all the tokens
     * @param user
     */

    public void revokeAllUserToken(AppUsers user){
        var validUserTokens = tokenRepository.findAllValidTokenUser(user.getUserID());
        if(validUserTokens.isEmpty()){
            return;
        }

        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });

        tokenRepository.saveAll(validUserTokens);
    }


    /**
     * This method is used to refresh a token
     * @param request
     * @param response
     * @throws IOException
     */

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String username;

        if (authHeader == null && !authHeader.startsWith("Bearer ")) {
            return;
        }

        refreshToken = authHeader.substring(7);
        username = pasetoService.extractUsername(refreshToken);
        if(username != null){
            var user = this.userRepository.findByUsername(username).orElseThrow();
            if (pasetoService.validateToken(refreshToken, user)){
                var accessToken = pasetoService.generateToken(user);
                revokeAllUserToken(user);
                saveUserToken(user, accessToken);
                var authResponse = AuthResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }

        }
    }
}
