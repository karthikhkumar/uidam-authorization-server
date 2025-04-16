package org.eclipse.ecsp.oauth2.server.core.request.transformer;

/**
 * IdpTransformer.
 */
public interface IdpTransformer {
    String transformUserName(Object value);

    String transformEmail(Object value);

    String transformAud(Object value);

    String transformFirstName(Object value);

    String transformLastName(Object value);

    String transformCountry(Object value);

    String transformState(Object value);

    String transformCity(Object value);

    String transformAddress1(Object value);

    String transformAddress2(Object value);

    String transformPostalCode(Object value);

    String transformPhoneNumber(Object value);

    String transformGender(Object value);
}