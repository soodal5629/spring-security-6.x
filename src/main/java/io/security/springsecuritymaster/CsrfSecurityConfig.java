package io.security.springsecuritymaster;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
@Slf4j
public class CsrfSecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // http 통신에 대한 인가 정책 설정
                .authorizeHttpRequests(auth -> auth
                        // csrf 기능이 자동으로 활성화되어 있기 때문에 POST와 같은 변경 요청이 올 경우 인증 에러나 로그인 화면으로 리다이렉션 될 수 있다
                        .requestMatchers("/csrf").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults()) // 폼 로그인 방식을 기본 default 방식으로 설정
                //.csrf(c -> c.disable())
                //.csrf(c -> c.ignoringRequestMatchers("/csrf"))
        ;
        return http.build();
    }

}
