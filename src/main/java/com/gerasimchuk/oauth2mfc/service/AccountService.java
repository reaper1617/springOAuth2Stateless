package com.gerasimchuk.oauth2mfc.service;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
public class AccountService {

    public UUID findOrRegisterAccount(
            @NonNull String socialUserId,
            @NonNull String socialUserProvider,
            @NonNull Map<String, Object> socialUserInfo
    ) {
        // here we actually persist user to our database
        log.info("Looking up or registering social user; id={}; provider={}; info={}", socialUserId, socialUserProvider, socialUserInfo);
        return UUID.randomUUID();
    }

}
