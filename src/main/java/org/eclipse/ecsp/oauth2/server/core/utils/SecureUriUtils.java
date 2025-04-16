package org.eclipse.ecsp.oauth2.server.core.utils;

import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.util.Map;


/**
 * Utility class for building secure redirect URIs.
 * This class provides methods to validate, sanitize, and encode URL inputs before constructing the redirect URI.
 */
public class SecureUriUtils {

    /**
     * Private constructor to prevent instantiation.
     */
    private SecureUriUtils() {
    }

    /**
     * Builds a redirect URI from a base URI and a map of URL inputs that need to be sanitized.
     *
     * @param baseUri The base URI to which the sanitized and encoded parameters will be appended.
     * @param urlInputsToBeSanitized A map containing the URL parameters to be sanitized and added to the base URI.
     * @return A string representing the constructed redirect URI.
     * @throws IllegalArgumentException If the base URI is invalid.
     */
    public static String buildRedirectUri(String baseUri, Map<String, String> urlInputsToBeSanitized) {
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(baseUri);

        if (!CollectionUtils.isEmpty(urlInputsToBeSanitized)) {
            for (Map.Entry<String, String> urlInput : urlInputsToBeSanitized.entrySet()) {
                String inputValToBeSanitized = urlInput.getValue();
                String sanitizedInpVal = sanitize(inputValToBeSanitized);
                String encodedInpVal = encode(sanitizedInpVal);
                uriBuilder.queryParam(urlInput.getKey(), encodedInpVal);
            }
        }
        return uriBuilder.build(true).toUriString();
    }


    /**
     * Sanitizes the input by removing all whitespace characters.
     *
     * @param input The input string to be sanitized.
     * @return The sanitized string.
     */
    private static String sanitize(String input) {
        return input.replaceAll("\\s+", "");
    }

    /**
     * Encodes the input using UTF-8 encoding scheme.
     *
     * @param input The input string to be encoded.
     * @return The encoded string.
     */
    private static String encode(String input) {
        return org.springframework.web.util.UriUtils.encode(input, StandardCharsets.UTF_8);
    }
}
