package org.eclipse.ecsp.oauth2.server.core.request.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Set;

/**
 * FederatedUserDto.
 */
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class FederatedUserDto extends BaseUserDto implements Serializable {
    private static final long serialVersionUID = 3018743707184880829L;
    @JsonProperty("identity_provider_name")
    private String identityProviderName;
    private Set<String> roles;
}
