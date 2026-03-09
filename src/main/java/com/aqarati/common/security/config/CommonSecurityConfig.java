package com.aqarati.common.security.config;

import com.aqarati.common.security.filter.JwtAuthenticationFilter;
import com.aqarati.common.security.service.TokenBlocklistService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Auto-configuration for common security components.
 */
@Configuration
@ComponentScan(basePackages = "com.aqarati.common.security")
@EnableWebSecurity
@RequiredArgsConstructor
public class CommonSecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Provides a default permissive TokenBlocklistService if the importing microservice
     * does not define its own (e.g. via Redis).
     */
    @Bean
    @ConditionalOnMissingBean(TokenBlocklistService.class)
    public TokenBlocklistService defaultTokenBlocklistService() {
        return new TokenBlocklistService() {
            @Override
            public boolean isBlocked(String jti) {
                // By default, no tokens are blocklisted unless a specific service overrides this bean.
                return false;
            }
        };
    }

    /**
     * Provides a basic stateless SecurityFilterChain that relies on JwtAuthenticationFilter.
     * Microservices can override this by defining their own SecurityFilterChain bean.
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain commonSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            // Stateless sessions
            .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Disable CSRF & CORS as they are typically handled at API Gateway level
            .cors(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable)
            // JWT Filter integration
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            // Require authentication for all endpoints by default
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/health", "/actuator/info", "/v3/api-docs/**", "/swagger-ui/**").permitAll()
                .anyRequest().authenticated()
            );

        return http.build();
    }
}
