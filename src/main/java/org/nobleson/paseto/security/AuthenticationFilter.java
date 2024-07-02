package org.nobleson.paseto.security;


import dev.paseto.jpaseto.Paseto;
import dev.paseto.jpaseto.Pasetos;
import dev.paseto.jpaseto.lang.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.Key;
import java.util.ArrayList;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {

    private final SecretKey sharedSecret;
   // private final UserDetailsService userDetailsService;

    public AuthenticationFilter() {
        this.sharedSecret = Keys.secretKey();
    }


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String token = getTokenFromRequest(request);

        if (StringUtils.hasText(token)) {
            try {
                Paseto paseto = Pasetos.parserBuilder()
                        .setSharedSecret( sharedSecret)
                        .build()
                        .parse(token);

                String username = paseto.getClaims().getSubject();

                if (username != null) {
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
                    auth.setDetails(new WebAuthenticationDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }

            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }

        filterChain.doFilter(request, response);
    }



    private String getTokenFromRequest(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if(StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            return token.substring(7);
        }

        return null;
    }
}
