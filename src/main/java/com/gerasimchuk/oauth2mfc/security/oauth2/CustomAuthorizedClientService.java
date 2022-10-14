package com.gerasimchuk.oauth2mfc.security.oauth2;

import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class CustomAuthorizedClientService implements OAuth2AuthorizedClientService {

    private final OAuthHelper oAuthHelper;

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        return null;
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        this.oAuthHelper.oauthSuccessCallback(authorizedClient, principal);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
    }

}
