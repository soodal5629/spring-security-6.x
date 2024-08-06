package io.security.springsecuritymaster.authenticationevent;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

//@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider2 implements AuthenticationProvider {
    // 스프링 시큐리티가 제공하는 이벤트 발행 방법
    private final AuthenticationEventPublisher authenticationEventPublisher;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(!authentication.getName().equals("user")) {
            authenticationEventPublisher.publishAuthenticationFailure(new BadCredentialsException("DisabledException"), authentication);
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
