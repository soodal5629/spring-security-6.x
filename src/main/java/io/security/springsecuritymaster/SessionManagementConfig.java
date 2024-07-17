package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
/**
 * 세션 관리 Config
 */
public class SessionManagementConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/invalidSessionUrl","/expiredUrl").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .sessionManagement(session -> session
                        // invalidSessionUrl 과 expiredUrl 모두 설정할 경우 invalidSessionUrl 설정이 동작함
                        .invalidSessionUrl("/invalidSessionUrl")
                        // 세션 제어 개수 설정해야 세션 제어하는 의미가 있음
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false) // default: false
                        .expiredUrl("/expiredUrl")
                )
        ;
        return http.build();
    }

}
