package org.eclipse.ecsp.oauth2.server.core.exception;

/**
 * Exception thrown when claim validation fails during the OAuth2 authentication process.
 */
public class ClaimValidationException extends RuntimeException {
    
    private static final long serialVersionUID = 5951820833972448569L;

    public ClaimValidationException(String message) {
        super(message);
    }

    public ClaimValidationException(String message, Throwable cause) {
        super(message, cause);
    }
} 