package org.aqarati.common.security.service;

public interface TokenBlocklistService {
    /**
     * Checks if a token ID (jti) has been blocklisted (e.g., due to logout).
     *
     * @param jti the JWT token ID
     * @return true if the token is blocked, false otherwise
     */
    boolean isBlocked(String jti);
}
