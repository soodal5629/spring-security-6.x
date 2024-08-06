package io.security.springsecuritymaster.authenticationevent;

import org.springframework.security.core.AuthenticationException;
/**
 * 커스텀 예외
 */
public class CustomException extends AuthenticationException {
    public CustomException(String msg) {
        super(msg);
    }
}