package io.security.springsecuritymaster.authorizationevent;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

//@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    // 스프링이 제공하는 이벤트 발행 방법
    private final ApplicationContext applicationContext;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(!authentication.getName().equals("user")) {
            // 실패 이벤트 발행
            applicationContext.publishEvent(new AuthenticationFailureProviderNotFoundEvent(authentication
                    , new BadCredentialsException("BadCredentialsException")));
            throw new BadCredentialsException("BadCredentialsException");
        }
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
