package org.eclipse.ecsp.oauth2.server.core.request.dto;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

/**
 * BaseUserDto.
 */
@Getter
@Setter
public class BaseUserDto {
    private String userName;
    private String lastName;
    private String country;
    private String state;
    private String city;
    @NotNull
    private String email;
    private String status;
    private String aud;
    @NotNull
    private String firstName;
    private String address1;
    private String address2;
    private String postalCode;
    private String phoneNumber;
    private String gender;
}
