package org.eclipse.ecsp.oauth2.server.core.exception;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Test cases for {@link ClaimValidationException}.
 */
class ClaimValidationExceptionTest {

    @Test
    void constructorWithMessage_ShouldSetMessage() {
        // Given
        String errorMessage = "Missing required claim: email";

        // When
        ClaimValidationException exception = new ClaimValidationException(errorMessage);

        // Then
        assertEquals(errorMessage, exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void constructorWithMessageAndCause_ShouldSetBoth() {
        // Given
        String errorMessage = "Invalid claim value";
        IllegalArgumentException cause = new IllegalArgumentException("Original error");

        // When
        ClaimValidationException exception = new ClaimValidationException(errorMessage, cause);

        // Then
        assertEquals(errorMessage, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

    @Test
    void exceptionShouldBeRuntimeException() {
        // When
        ClaimValidationException exception = new ClaimValidationException("test");

        // Then
        assertTrue(exception instanceof RuntimeException);
    }
}