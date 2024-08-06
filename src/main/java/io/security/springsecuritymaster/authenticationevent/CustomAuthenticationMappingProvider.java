package io.security.springsecuritymaster.authenticationevent;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
//@Component
public class CustomAuthenticationMappingProvider implements AuthenticationProvider {
    private final AuthenticationEventPublisher authenticationEventPublisher;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(authentication.getName().equals("admin")) {
            // 커스텀 예외 전달 -> 매핑된 커스텀 이벤트 발행
            authenticationEventPublisher.publishAuthenticationFailure(new CustomException("CustomException"), authentication);
            throw new CustomException("CustomException");
        }
        else if(authentication.getName().equals("db")) {
            // 커스텀 예외 전달 -> 기본 설정된 이벤트 발행
            authenticationEventPublisher.publishAuthenticationFailure(new DefaultAuthenticationException("DefaultAuthenticationException"), authentication);
            throw new DefaultAuthenticationException("DefaultAuthenticationException");
        }
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
