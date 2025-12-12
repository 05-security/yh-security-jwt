package io.yh.security.social;

import io.yh.security.member.model.YhMemberDetails;

import java.util.Map;

/**
 * Maps OAuth2 provider registration + attributes into {@link YhMemberDetails}.
 * Override this bean to plug your own user mapping/persistence logic.
 */
public interface SocialUserMapper {
    YhMemberDetails<?> map(String registrationId, Map<String, Object> attributes);
}
