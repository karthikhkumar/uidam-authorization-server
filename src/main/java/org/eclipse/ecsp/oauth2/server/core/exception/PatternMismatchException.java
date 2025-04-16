package org.eclipse.ecsp.oauth2.server.core.exception;

/**
 * Custom exception for pattern mismatch errors.
 */
public class PatternMismatchException extends RuntimeException {

    /**
     * Default constructor.
     */
    public PatternMismatchException() {
        super();
    }

    /**
     * Constructor with a custom message.
     *
     * @param message The custom message for the exception.
     */
    public PatternMismatchException(String message) {
        super(message);
    }

    /**
     * Constructor with a custom message and a cause.
     *
     * @param message The custom message for the exception.
     * @param cause The cause of the exception.
     */
    public PatternMismatchException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructor with a cause.
     *
     * @param cause The cause of the exception.
     */
    public PatternMismatchException(Throwable cause) {
        super(cause);
    }
}