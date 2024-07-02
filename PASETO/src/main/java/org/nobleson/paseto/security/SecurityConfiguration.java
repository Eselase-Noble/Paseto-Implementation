package org.nobleson.paseto.security;


import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import static org.nobleson.paseto.enums.Role.ADMIN;
import static org.nobleson.paseto.enums.Role.MANAGER;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.http.HttpMethod.DELETE;
import static org.nobleson.paseto.enums.Permission.*;

@EnableWebSecurity
@Configuration
@EnableAutoConfiguration
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final AuthenticationFilter authenticationFilter;
    private final AuthenticationProvider authenticationProvider;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.disable())
                .csrf(csrf -> csrf.disable())
                .authorizeRequests(authorizedRequests ->
                        authorizedRequests
                                .requestMatchers("/paseto/user/auth/**")
                                .permitAll()
                                .requestMatchers("/paseto/api/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                                .requestMatchers(GET, "/payrollsystem/v1/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name() )
                                .requestMatchers(POST, "/payrollsystem/v1/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                                .requestMatchers(PUT, "/payrollsystem/v1/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                                .requestMatchers(DELETE, "/payrollsystem/v1/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())
                                .anyRequest()
                                .authenticated())
                .sessionManagement(sessionManagement-> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();

    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("http://127.0.0.1");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/paseto/**", configuration);
        return source;

    }





}
