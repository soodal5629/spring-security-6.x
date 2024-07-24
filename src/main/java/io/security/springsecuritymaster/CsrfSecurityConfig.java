package io.security.springsecuritymaster;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

@EnableWebSecurity
@Configuration
@Slf4j
public class CsrfSecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // CSRF 토큰을 쿠키에 저장
        // CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();

        // csrf 토큰 default 핸들러(설정 안해도 얘가 적용됨)
        XorCsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new XorCsrfTokenRequestAttributeHandler();
        // 지연 로딩하지 않고 모든 http 요청에 대해 csrf 토큰을 가져오고 싶을 경우 이와 같이 설정 (성능 저하되므로 권장 X)
        //csrfTokenRequestAttributeHandler.setCsrfRequestAttributeName(null);

        http
                // http 통신에 대한 인가 정책 설정
                .authorizeHttpRequests(auth -> auth
                        // csrf 기능이 자동으로 활성화되어 있기 때문에 POST와 같은 변경 요청이 올 경우 인증 에러나 로그인 화면으로 리다이렉션 될 수 있다
                        .requestMatchers("/csrf", "/csrfToken", "/form", "/formCsrf").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults()) // 폼 로그인 방식을 기본 default 방식으로 설정
                // JS 에서 쿠키를 읽을 수 있는 설정
                // .csrf(c -> c
                        //.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                //        .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler))
                //.csrf(c -> c.disable())
                //.csrf(c -> c.ignoringRequestMatchers("/csrf")
                .csrf(Customizer.withDefaults())
        ;
        return http.build();
    }

}
