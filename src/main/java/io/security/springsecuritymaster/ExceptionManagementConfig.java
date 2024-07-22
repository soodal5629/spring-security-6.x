package io.security.springsecuritymaster;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

@EnableWebSecurity
@Configuration
/**
 * 예외 처리 관리 Config
 */
@Slf4j
public class ExceptionManagementConfig {
    //@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/loginPage").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new AuthenticationEntryPoint() {
                            // 인증에 실패했을 경우 어떻게 할 것인지 처리
                            @Override
                            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                                log.info("exception : {}", authException.getMessage());
                                response.sendRedirect("/loginPage");
                            }
                        })
                        .accessDeniedHandler(new AccessDeniedHandler() {
                            // 인가 실패 시 핸들링
                            @Override
                            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                                log.info("exception : {}", accessDeniedException.getMessage());
                                response.sendRedirect("/denied");
                            }
                        })
                )
        ;
        return http.build();
    }

}
