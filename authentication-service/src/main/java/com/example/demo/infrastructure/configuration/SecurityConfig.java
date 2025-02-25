package com.example.demo.infrastructure.configuration;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpHeaders;


import com.example.demo.domain.entity.Token;
import com.example.demo.infrastructure.repository.TokenRepository;

import jakarta.servlet.Filter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	private AuthenticationProvider authenticationProvider;
	
	@Autowired
	private TokenRepository tokenRepository;
	
	@Autowired
	private JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(req -> req
            		.requestMatchers("/auth/**")
            		.permitAll()
            		.anyRequest()
            		.authenticated()
            )
            .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
            .authenticationProvider(authenticationProvider)
            .addFilterBefore((Filter) jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .logout(logout ->
            	logout.logoutUrl("/auth/logout")
            		.addLogoutHandler((request, response, authentication) -> {
            			String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            			logout(authHeader);
            		})
            		.logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
            		); 
        return http.build();
    }

	private void logout(String token) {
		if (token == null || !token.startsWith("Bearer ")) {
			throw new IllegalArgumentException("invalid Token");
		}
		
		String jwtToken = token.substring(7);
		Token foundToken = tokenRepository.findByToken(jwtToken)
				.orElseThrow(() -> new IllegalArgumentException("Invalid Token "));
		
		foundToken.setExpired(true);
		foundToken.setRevoked(true);
		tokenRepository.save(foundToken);
		
	}
}




