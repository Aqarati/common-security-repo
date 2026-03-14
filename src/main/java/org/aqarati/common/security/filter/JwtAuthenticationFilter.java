package org.aqarati.common.security.filter;

import org.aqarati.common.security.model.AuthenticatedUser;
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

        // Extract identity from JWT claims — no database call needed
        String email  = jwtValidationUtil.getEmail(token);
        String userId = jwtValidationUtil.getUserId(token);

        AuthenticatedUser principal = new AuthenticatedUser(userId, email);
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(principal, null, authorities);

        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.debug("Authenticated request for user={}", email);
        chain.doFilter(request, response);
    }
}
