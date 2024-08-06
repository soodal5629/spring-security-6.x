package io.security.springsecuritymaster.authorizationevent;

import org.springframework.security.core.AuthenticationException;
/**
 * 커스텀 예외
 */
public class DefaultAuthenticationException extends AuthenticationException {
    public DefaultAuthenticationException(String msg) {
        super(msg);
    }
}
