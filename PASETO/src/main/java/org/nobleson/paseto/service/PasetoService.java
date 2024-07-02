package org.nobleson.paseto.service;


import dev.paseto.jpaseto.Claims;
import dev.paseto.jpaseto.Paseto;
import dev.paseto.jpaseto.PasetoBuilder;
import dev.paseto.jpaseto.Pasetos;
import dev.paseto.jpaseto.lang.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class PasetoService {
//    @Value("${application.security.jwt.secret_key}")
//    private String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long expiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;


    private final SecretKey secretKey;

    public PasetoService() {
        this.secretKey = Keys.secretKey();
    }


    public String extractUsername(String token) {

        Paseto paseto = Pasetos.parserBuilder()
                .setSharedSecret(secretKey)
                .build()
                .parse(token);
        String username = paseto.getClaims().getSubject();
        return username;
    }

    public <T> T extractClaim(String token, Function<Map<String, Object>, T> claimsResolver) {
    final Map<String , Object> claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
    }

    public String generateToken(Map<String, Object> claims,UserDetails userDetails) {
        return buildToken(new HashMap<String, Object>(), userDetails, expiration);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }


    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return ((username.equals(userDetails.getUsername())) && !isTokenExpired(token));
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token){
        return extractClaim(token, claims->Date.from(Instant.parse((String) claims.get("exp"))));
    }


    public Claims extractAllClaims(String token){

        Paseto paseto = Pasetos
                .parserBuilder()
                .setSharedSecret(secretKey)
                .build()
                .parse(token);

        return paseto.getClaims();
    }
    public String buildToken(Map<String, Object> claims, UserDetails userDetails, long expiration) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusMillis(expiration);
       PasetoBuilder pasetoBuilder = Pasetos.V2.LOCAL.builder()
                .setSharedSecret(secretKey)
                .setIssuedAt(now)
                .setExpiration(expiresAt)
                .claim("sub", userDetails.getUsername());
       claims.forEach(pasetoBuilder::claim);

       return pasetoBuilder.compact();


    }

    public Key getSignInKey(){
        byte[] keyBytes = java.util.Base64.getDecoder().decode("Basic " + secretKey.getAlgorithm());
        return new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
    }
}
