package org.aqarati.common.security.model;

import java.security.Principal;

/**
 * Typed principal that carries both the immutable user ID and the email
 * extracted from the JWT.  Stored in the SecurityContext so every service
 * can access identity without an extra DB call.
 */
public record AuthenticatedUser(String userId, String email) implements Principal {

    @Override
    public String getName() {
        return userId;   // stable identifier — never changes
    }
}
