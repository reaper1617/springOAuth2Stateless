package com.gerasimchuk.oauth2mfc.security.oauth2;

import com.gerasimchuk.oauth2mfc.security.helper.AuthenticationHelper;
import com.gerasimchuk.oauth2mfc.security.helper.CookieHelper;
import com.gerasimchuk.oauth2mfc.service.AccountService;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.UUID;

@Component
public class OAuthHelper {

    public static final String OAUTH_COOKIE_NAME = "OAUTH";
    public static final String SESSION_COOKIE_NAME = "SESSION";

    private final AccountService accountService;
    private final AuthenticationHelper authenticationHelper;
    private final CookieHelper cookieHelper;

    @Autowired
    public OAuthHelper(AccountService accountService, AuthenticationHelper authenticationHelper, CookieHelper cookieHelper) {
        this.accountService = accountService;
        this.authenticationHelper = authenticationHelper;
        this.cookieHelper = cookieHelper;
    }

    @SneakyThrows
    public void oauthRedirectResponse(HttpServletRequest request, HttpServletResponse response, String url) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"redirectUrl\": \"%s\" }".formatted(url));
    }

    @SneakyThrows
    public void oauthSuccessCallback(OAuth2AuthorizedClient client, Authentication authentication) {
        //  access + refresh tokens  in the "client"

        // Save user session to the Redis can be done here

        UUID accountId = this.accountService.findOrRegisterAccount(
                authentication.getName(),
                authentication.getName().split("\\|")[0],
                ((DefaultOidcUser) authentication.getPrincipal()).getClaims()
        );
        authenticationHelper.attachAccountId(authentication, accountId.toString());
    }

    @SneakyThrows
    public void oauthSuccessResponse(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String accountId = authenticationHelper.retrieveAccountId(authentication);
        response.addHeader(HttpHeaders.SET_COOKIE, cookieHelper.generateExpiredCookie(OAUTH_COOKIE_NAME));
        response.addHeader(HttpHeaders.SET_COOKIE, cookieHelper.generateCookie(SESSION_COOKIE_NAME, accountId, Duration.ofDays(1)));
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        response.getWriter().write("{ \"status\": \"success\" }");
        response.setContentType(MediaType.TEXT_HTML_VALUE);
        response.getWriter().write(getSuccessHtml());
    }

    @SneakyThrows
    public void oauthFailureResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.SET_COOKIE, cookieHelper.generateExpiredCookie(OAUTH_COOKIE_NAME));
        response.getWriter().write("{ \"status\": \"failure\" }");
    }

    @SneakyThrows
    public void onAccessDenied(HttpServletRequest request, HttpServletResponse response, Exception authException) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"Access Denied\" }");
    }

    // тут чистый html, поскольку я задолбался писать и отлаживать js код отрисовки html
    // пристрелите меня
    private String getSuccessHtml() {
        return "<!DOCTYPE html>\n" +
                "<html lang=\"en\">\n" +
                "<head>\n" +
                "    <meta charset=\"UTF-8\">\n" +
                "    <title>Callback</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "<h1>Callback: success</h1>\n" +
                "<button><a href=\"/\">Home</a></button>\n" +
                "<button><a href=\"/profile.html\">Profile</a></button>\n" +
                "</body>\n" +
                "</html>";
    }

}
