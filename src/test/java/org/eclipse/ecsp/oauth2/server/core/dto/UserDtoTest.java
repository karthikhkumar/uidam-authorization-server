package org.eclipse.ecsp.oauth2.server.core.dto;

import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserDtoTest {

    @Test
    void firstName_canBeSetAndRetrieved() {
        UserDto user = new UserDto();
        user.setFirstName("John");
        assertEquals("John", user.getFirstName());
    }

    @Test
    void lastName_canBeSetAndRetrieved() {
        UserDto user = new UserDto();
        user.setLastName("Doe");
        assertEquals("Doe", user.getLastName());
    }

    @Test
    void email_canBeSetAndRetrieved() {
        UserDto user = new UserDto();
        user.setEmail("john.doe@example.com");
        assertEquals("john.doe@example.com", user.getEmail());
    }

    @Test
    void roles_canBeSetAndRetrieved() {
        UserDto user = new UserDto();
        List<String> roles = List.of("USER", "ADMIN");
        user.setRoles(roles);
        assertEquals(roles, user.getRoles());
    }

    @Test
    void notificationConsent_canBeSetAndRetrieved() {
        UserDto user = new UserDto();
        user.setNotificationConsent(true);
        assertTrue(user.isNotificationConsent());
    }

    @Test
    void firstName_defaultIsNull() {
        UserDto user = new UserDto();
        assertEquals(null, user.getFirstName());
    }

    @Test
    void roles_defaultIsEmptyList() {
        UserDto user = new UserDto();
        assertEquals(null, user.getRoles());
    }

    @Test
    void allFields_canBeSetAndRetrieved() {
        UserDto user = new UserDto();
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setCountry("USA");
        user.setState("California");
        user.setCity("Los Angeles");
        user.setAddress1("123 Main St");
        user.setAddress2("Apt 4B");
        user.setPostalCode("90001");
        user.setPhoneNumber("123-456-7890");
        user.setEmail("john.doe@example.com");
        user.setGender("Male");
        user.setBirthDate("1990-01-01");
        user.setLocale("en_US");
        user.setNotificationConsent(true);
        user.setTimeZone("PST");
        user.setUserName("johndoe");
        user.setPassword("password");
        user.setRoles(List.of("USER", "ADMIN"));
        user.setStatus("Active");
        user.setAud("audience");

        assertEquals("John", user.getFirstName());
        assertEquals("Doe", user.getLastName());
        assertEquals("USA", user.getCountry());
        assertEquals("California", user.getState());
        assertEquals("Los Angeles", user.getCity());
        assertEquals("123 Main St", user.getAddress1());
        assertEquals("Apt 4B", user.getAddress2());
        assertEquals("90001", user.getPostalCode());
        assertEquals("123-456-7890", user.getPhoneNumber());
        assertEquals("john.doe@example.com", user.getEmail());
        assertEquals("Male", user.getGender());
        assertEquals("1990-01-01", user.getBirthDate());
        assertEquals("en_US", user.getLocale());
        assertTrue(user.isNotificationConsent());
        assertEquals("PST", user.getTimeZone());
        assertEquals("johndoe", user.getUserName());
        assertEquals("password", user.getPassword());
        assertEquals(List.of("USER", "ADMIN"), user.getRoles());
        assertEquals("Active", user.getStatus());
        assertEquals("audience", user.getAud());
    }
}