package io.yh.security.social;

import io.yh.security.member.model.YhMemberDetails;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Delegates to default userinfo, then maps attributes into {@link YhMemberDetails} via {@link SocialUserMapper}.
 */
public class YhOAuth2UserService extends DefaultOAuth2UserService {

    private final SocialUserMapper socialUserMapper;

    public YhOAuth2UserService(SocialUserMapper socialUserMapper) {
        this.socialUserMapper = socialUserMapper;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        return socialUserMapper.map(userRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
    }
}
