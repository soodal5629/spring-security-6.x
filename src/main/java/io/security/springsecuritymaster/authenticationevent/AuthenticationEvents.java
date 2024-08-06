package io.security.springsecuritymaster.authenticationevent;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.*;
import org.springframework.stereotype.Component;

/**
 * 인증 이벤트 수신
 */
@Component
@Slf4j
public class AuthenticationEvents {
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        log.info("success event = {} {}", event.getClass(), event.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        log.info("failure event = {} {}", event.getClass(), event.getException().getMessage());
    }

    @EventListener
    public void onSuccess(InteractiveAuthenticationSuccessEvent event) {
        log.info("success event = {} {}", event.getClass(), event.getAuthentication().getName());
    }

    @EventListener
    public void onSuccess(CustomAuthenticationSuccessEvent event) {
        log.info("custom success event = {} {}", event.getClass(), event.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        log.info("failure event = {} {}", event.getClass(), event.getException().getMessage());
    }

    @EventListener
    public void onFailure(AuthenticationFailureProviderNotFoundEvent event) {
        log.info("failure event = {} {}", event.getClass(), event.getException().getMessage());
    }

    @EventListener
    public void onFailure(CustomAuthenticationFailureEvent event) {
        log.info("custom failure event = {} {}", event.getClass(), event.getException().getMessage());
    }

    @EventListener
    public void onFailure(DefaultAuthenticationFailureEvent event) {
        log.info("custom failure event = {} {}", event.getClass(), event.getException().getMessage());
    }
}
