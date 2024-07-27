package io.security.springsecuritymaster;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

@Configuration
public class CustomAuthorizationSecurityConfig {
    //@Bean
    // 스프링 시큐리티가 제공하는 WebExpressionAuthorizationManager을 통해 표현식을 사용해서 권한 규칙 설정
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/user/{name}")
                    .access(new WebExpressionAuthorizationManager("#name == authentication.name"))
                .requestMatchers("/admin/db")
                    .access(new WebExpressionAuthorizationManager("hasAuthority('ROLE_DB') or hasAuthority('ROLE_ADMIN')"))
                .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    // 커스텀 권한 표현식 구현
    //@Bean(name = "securityFilterChain")
    public SecurityFilterChain securityFilterChain2(HttpSecurity http, ApplicationContext context) throws Exception {
        DefaultHttpSecurityExpressionHandler expressionHandler = new DefaultHttpSecurityExpressionHandler();
        expressionHandler.setApplicationContext(context);

        // 사용법이 이전 버젼보다 간단해짐
        WebExpressionAuthorizationManager authorizationManager =
                new WebExpressionAuthorizationManager("@customWebSecurity.check(authentication, request)");
        authorizationManager.setExpressionHandler(expressionHandler);

        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/custom/**").access(authorizationManager)
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    // 커스텀 RequestMatcher 사용
    @Bean(name = "securityFilterChain")
    public SecurityFilterChain securityFilterChain3(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers(new CustomRequestMatcher("/admin")).hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }


}
