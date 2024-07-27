package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityMatcherConfig {
    @Bean
    // 지금까지 했던 것과 마찬가지로 모든 요청에 대해 수행
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    // securityMatcher 사용
    @Bean
    @Order(1) // 해당 빈이 먼저 실행
    public SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        http.securityMatchers(matcher -> matcher.requestMatchers("/api/**", "/oauth/**"))
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll());

        return http.build();
    }
}
