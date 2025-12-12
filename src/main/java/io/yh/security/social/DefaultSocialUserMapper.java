package io.yh.security.social;

import io.yh.security.member.model.YhMemberDetails;
import io.yh.security.member.social.YhGoogleOAuthMemberDetails;
import io.yh.security.member.social.YhOAuthMemberDetails;

import java.util.Map;
import java.util.Set;

/**
 * Basic mapper that converts Google (sub/email/name/picture) attributes into {@link YhMemberDetails}.
 * Other providers fall back to email/sub/id for username with ROLE_USER.
 */
public class DefaultSocialUserMapper implements SocialUserMapper {

    @Override
    public YhMemberDetails<?> map(String registrationId, Map<String, Object> attributes) {
        YhOAuthMemberDetails details = buildDetails(registrationId, attributes);
        Set<String> roles = Set.of("ROLE_USER");
        return new YhMemberDetails<>(
                details,
                YhOAuthMemberDetails::getEmail,
                user -> "",
                user -> roles
        );
    }

    private YhOAuthMemberDetails buildDetails(String registrationId, Map<String, Object> attributes) {
        if ("google".equalsIgnoreCase(registrationId)) {
            return new YhGoogleOAuthMemberDetails(attributes);
        }
        return new GenericOAuthMemberDetails(attributes);
    }

    private static class GenericOAuthMemberDetails implements YhOAuthMemberDetails {
        private final Map<String, Object> attributes;

        GenericOAuthMemberDetails(Map<String, Object> attributes) {
            this.attributes = attributes;
        }

        @Override
        public String getProviderId() {
            return stringAttr("sub", stringAttr("id", stringAttr("user_id", "")));
        }

        @Override
        public String getEmail() {
            return stringAttr("email", stringAttr("login", stringAttr("username", getProviderId())));
        }

        @Override
        public String getName() {
            return stringAttr("name", getEmail());
        }

        @Override
        public String getPicture() {
            return stringAttr("picture", stringAttr("avatar_url", ""));
        }

        @Override
        public java.util.Map<String, Object> getAttributes() {
            return attributes;
        }

        private String stringAttr(String key, String defaultValue) {
            Object value = attributes.get(key);
            return value instanceof String str ? str : defaultValue;
        }
    }
}
