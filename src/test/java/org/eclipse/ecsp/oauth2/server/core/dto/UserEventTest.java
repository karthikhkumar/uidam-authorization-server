package org.eclipse.ecsp.oauth2.server.core.dto;

import org.eclipse.ecsp.oauth2.server.core.request.dto.UserEvent;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class UserEventTest {

    @Test
    void type_canBeSetAndRetrieved() {
        UserEvent event = new UserEvent();
        event.setType("LOGIN");
        assertEquals("LOGIN", event.getType());
    }

    @Test
    void result_canBeSetAndRetrieved() {
        UserEvent event = new UserEvent();
        event.setResult("SUCCESS");
        assertEquals("SUCCESS", event.getResult());
    }

    @Test
    void message_canBeSetAndRetrieved() {
        UserEvent event = new UserEvent();
        event.setMessage("User logged in successfully.");
        assertEquals("User logged in successfully.", event.getMessage());
    }

    @Test
    void type_defaultIsNull() {
        UserEvent event = new UserEvent();
        assertEquals(null, event.getType());
    }

    @Test
    void result_defaultIsNull() {
        UserEvent event = new UserEvent();
        assertEquals(null, event.getResult());
    }

    @Test
    void message_defaultIsNull() {
        UserEvent event = new UserEvent();
        assertEquals(null, event.getMessage());
    }
}