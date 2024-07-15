package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@EnableWebSecurity
@Configuration
/**
 * CustomAuthenticationProvider 추가 Config
 */
public class SecurityConfigAuthenticationProviderConfig {
    //@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManagerBuilder builder
            , AuthenticationConfiguration configuration) throws Exception {
        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        // bean으로 등록된 것을 추가
        managerBuilder.authenticationProvider(customAuthenticationProvider());
        // parent의 AuthenticationProvider를 DaoAuthenticationProvider로 다시 배치
        ProviderManager authenticationManager = (ProviderManager) configuration.getAuthenticationManager();
        authenticationManager.getProviders().remove(0);
        builder.authenticationProvider(new DaoAuthenticationProvider());

        // 일반 객체로 생성하여 AuthenticationProvider 추가 방법 1
        //builder.authenticationProvider(new CustomAuthenticationProvider());

        http
                .authorizeHttpRequests(auth -> auth
                        //.requestMatchers("/").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                // 일반 객체로 생성하여 AuthenticationProvider 추가 방법 2
                //.authenticationProvider(new CustomAuthenticationProvider2())
        ;
        return http.build();
    }

    // 1개의 빈으로 등록하여 AuthenticationProvider 추가
    @Bean
    public AuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }
}
