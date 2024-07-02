package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // http 통신에 대한 인가 정책 설정
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // 인증 실패 시 인증 받도록 하는 방식 설정
                // 폼 로그인 방식을 기본 default 방식으로 설정
                .formLogin(Customizer.withDefaults());
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
