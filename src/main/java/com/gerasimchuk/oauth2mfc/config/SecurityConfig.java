package com.gerasimchuk.oauth2mfc.config;

import com.gerasimchuk.oauth2mfc.security.oauth2.CustomAuthorizationRedirectFilter;
import com.gerasimchuk.oauth2mfc.security.oauth2.CustomAuthorizedClientService;
import com.gerasimchuk.oauth2mfc.security.oauth2.CustomStatelessAuthorizationRequestRepository;
import com.gerasimchuk.oauth2mfc.security.oauth2.OAuthHelper;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {


    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;

    private static final String GOOGLE_REGISTRATION_ID = "google";

    private final CustomStatelessAuthorizationRequestRepository authorizationRequestRepository;
    private final CustomAuthorizedClientService authorizedClientService;
    private final OAuthHelper oAuthHelper;

    @Autowired
    public SecurityConfig(CustomStatelessAuthorizationRequestRepository authorizationRequestRepository,
                          CustomAuthorizedClientService authorizedClientService,
                          OAuthHelper oAuthHelper) {
        this.authorizationRequestRepository = authorizationRequestRepository;
        this.authorizedClientService = authorizedClientService;
        this.oAuthHelper = oAuthHelper;
    }

    @Bean
    @SneakyThrows
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        http
                .authorizeHttpRequests(cfg -> cfg.anyRequest().permitAll())
                .sessionManagement(cfg -> cfg.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(cfg -> {
                    cfg.successHandler(oAuthHelper::oauthSuccessResponse);
                    cfg.failureHandler(oAuthHelper::oauthFailureResponse);
                    cfg.authorizationEndpoint(subcfg -> {
                        subcfg.baseUri("oauth2/authorization");
                        subcfg.authorizationRequestRepository(authorizationRequestRepository);
                        subcfg.authorizationRequestResolver(authorizationRequestResolver());
                    });
                    cfg.authorizedClientService(authorizedClientService);
                })
                .addFilterBefore(customAuthorizationRedirectFilter(), OAuth2AuthorizationRequestRedirectFilter.class)
                .exceptionHandling(
                        cfg -> {
                            cfg.accessDeniedHandler(oAuthHelper::onAccessDenied);
                            cfg.authenticationEntryPoint(oAuthHelper::onAccessDenied);
                        }
                );

        return http.build();
    }

    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver() {
        return new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository(), "/oauth2/authorization");
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        var clientRegistration = CommonOAuth2Provider.GOOGLE.getBuilder(GOOGLE_REGISTRATION_ID)
                .clientId(googleClientId)
                .clientSecret(googleClientSecret)
                .build();
        return new InMemoryClientRegistrationRepository(clientRegistration);
    }

    @Bean
    public CustomAuthorizationRedirectFilter customAuthorizationRedirectFilter() {
        return new CustomAuthorizationRedirectFilter(
                oAuthHelper, authorizationRequestResolver(), authorizationRequestRepository
        );
    }
}
