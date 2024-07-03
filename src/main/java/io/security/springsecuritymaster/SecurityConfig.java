package io.security.springsecuritymaster;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@EnableWebSecurity
@Configuration
@Slf4j
public class SecurityConfig {
    //@Bean("securityFilterChain")
    public SecurityFilterChain basicSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                //.httpBasic(Customizer.withDefaults()); -> 대부분 basic 설정으로 써도 되긴 함
                // custom 하게 설정
                .httpBasic(basic -> basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));

        return http.build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // http 통신에 대한 인가 정책 설정
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // 인증 실패 시 인증 받도록 하는 방식 설정

                //.formLogin(Customizer.withDefaults()); // 폼 로그인 방식을 기본 default 방식으로 설정
                .formLogin(form -> form
                        //.loginPage("/loginPage")
                        .loginProcessingUrl("/loginProc")
                        // always use를 false 로 주면 인증 전에 가려고 했던 url로 리다이렉트
                        .defaultSuccessUrl("/", true)
                        .failureUrl("/failed")
                        .usernameParameter("userId")
                        .passwordParameter("pwd")
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                log.info("authentication : {}", authentication);
                                response.sendRedirect("/home");
                            }
                        })
                        .failureHandler(new AuthenticationFailureHandler() {
                            @Override
                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                log.info("exception {}", exception.getMessage());
                                response.sendRedirect("/login");
                            }
                        })
                        .permitAll()
                )
                .rememberMe(r -> r
                        //.alwaysRemember(true) // default: false
                        .tokenValiditySeconds(3600) // 1시간
                        .userDetailsService(userDetailsService())
                        .rememberMeParameter("remember")
                        .rememberMeCookieName("remember")
                        .key("security")
                )
        ;
        return http.build();
    }

    // application.yml 파일 설정보다 더 우선순위를 가짐
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}1234")
                .roles("USER").build();
        UserDetails user2 = User.withUsername("user2")
                .password("{noop}1111")
                .roles("USER").build();
        // user 객체 여러개 생성 가능
        return new InMemoryUserDetailsManager(user, user2);
    }
}
