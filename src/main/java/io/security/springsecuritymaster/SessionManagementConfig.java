package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
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
                        //.sessionFixation(f -> f.none()) -> 이건 대응하지 못하므로 의미가 없음. 사용하지 말 것
                        // default: changeSessionId -> 기본이므로 해당 설정 생략해도 동작(권장)
                        .sessionFixation(f -> f.changeSessionId())
                        // 세션 생성 전략(default: IF_REQUIRED)
                        //.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
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
