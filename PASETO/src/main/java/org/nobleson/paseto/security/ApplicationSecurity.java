package org.nobleson.paseto.security;


import lombok.RequiredArgsConstructor;
import org.nobleson.paseto.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationSecurity {
    private final UserRepository userRepository;


    @Bean
    public UserDetailsService getUserDetailsService() {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(()-> new UsernameNotFoundException("User not found"));
    }

    @Bean
    public AuthenticationProvider getAuthenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(getUserDetailsService());
        authenticationProvider.setPasswordEncoder(getPasswordEncoder());
        return authenticationProvider;
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(getUserDetailsService()).passwordEncoder(getPasswordEncoder());
//    }

    @Bean
    public AuthenticationManager getAuthenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
