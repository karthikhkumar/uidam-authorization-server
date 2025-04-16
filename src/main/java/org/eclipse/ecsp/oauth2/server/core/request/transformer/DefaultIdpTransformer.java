package org.eclipse.ecsp.oauth2.server.core.request.transformer;

import org.springframework.stereotype.Component;

/**
 * DefaultIdpTransformer.
 */
@Component
public class DefaultIdpTransformer implements IdpTransformer {

    @Override
    public String transformUserName(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformEmail(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformAud(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformFirstName(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformLastName(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformCountry(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformState(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformCity(Object value) {
        return null;
    }

    @Override
    public String transformAddress1(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformAddress2(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformPostalCode(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformPhoneNumber(Object value) {
        return String.valueOf(value);
    }

    @Override
    public String transformGender(Object value) {
        return String.valueOf(value);
    }

}