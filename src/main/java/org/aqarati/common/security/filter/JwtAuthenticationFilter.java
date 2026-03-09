package org.aqarati.common.security.filter;

import org.aqarati.common.security.service.TokenBlocklistService;
import org.aqarati.common.security.util.JwtValidationUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtValidationUtil jwtValidationUtil;
    private final TokenBlocklistService blocklistService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // Resolve token from Authorization header
        String token = jwtValidationUtil.resolveToken(request).orElse(null);

        if (token == null || !jwtValidationUtil.validateToken(token)) {
            chain.doFilter(request, response);
            return;
        }

        // Reject tokens that have been explicitly revoked (logout)
        String jti = jwtValidationUtil.getJti(token);
        if (blocklistService.isBlocked(jti)) {
            log.warn("Rejected blocklisted JWT jti={}", jti);
            chain.doFilter(request, response);
            return;
        }

        // Extract identity from JWT claims — no database call needed
        String email  = jwtValidationUtil.getEmail(token);
        String userId = jwtValidationUtil.getUserId(token);

        // Build authorities from claims - For general services, we default to ROLE_USER
        // Note: Could be expanded to parse 'role' claim if we want to support ROLE_ADMIN here
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(email, userId, authorities);

        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.debug("Authenticated request for user={}", email);
        chain.doFilter(request, response);
    }
}
