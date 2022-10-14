package com.gerasimchuk.oauth2mfc.security.helper;

import lombok.NonNull;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import java.time.Duration;
import java.util.Optional;

import static java.util.Objects.isNull;

@Component
public class CookieHelper {

    private static final String COOKIE_DOMAIN = "localhost";
    private static final Boolean HTTP_ONLY = Boolean.TRUE;
    private static final Boolean SECURE = Boolean.FALSE;

    public Optional<String> retrieve(Cookie[] cookies, @NonNull String name) {
        if (isNull(cookies)) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (cookie.getName().equalsIgnoreCase(name)) {
                return Optional.ofNullable(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    public String generateCookie(@NonNull String name, @NonNull String value, @NonNull Duration maxAge) {
        // Build cookie instance
        Cookie cookie = new Cookie(name, value);
        if (!"localhost".equals(COOKIE_DOMAIN)) { // https://stackoverflow.com/a/1188145
            cookie.setDomain(COOKIE_DOMAIN);
        }
        cookie.setHttpOnly(HTTP_ONLY);
        cookie.setSecure(SECURE);
        cookie.setMaxAge((int) maxAge.toSeconds());
        cookie.setPath("/");
        // Generate cookie string
        Rfc6265CookieProcessor processor = new Rfc6265CookieProcessor();
        return processor.generateHeader(cookie);
    }

    public String generateExpiredCookie(@NonNull String name) {
        return generateCookie(name, "-", Duration.ZERO);
    }

}
