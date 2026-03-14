package org.aqarati.common.security.config;

import org.aqarati.common.security.filter.JwtAuthenticationFilter;
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
@ComponentScan(basePackages = "org.aqarati.common.security")
@EnableWebSecurity
public class CommonSecurityConfig {

    /**
     * Provides a basic stateless SecurityFilterChain that relies on JwtAuthenticationFilter.
     * Microservices can override this by defining their own SecurityFilterChain bean.
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain commonSecurityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
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
