package org.eclipse.ecsp.oauth2.server.core.metrics;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * Represents metric information including type and tags.
 *
 * @since 1.0
 */
@Builder
@Getter
@Setter
public class MetricInfo {

    private MetricType metricType;
    private String[] tags;

}
