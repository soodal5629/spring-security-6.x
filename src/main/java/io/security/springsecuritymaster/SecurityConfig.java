package io.security.springsecuritymaster;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

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

    //@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setMatchingRequestParameterName("customParam=y");
        // AuthenticationManagerBuilder를 통한 AuthenticationManager 생성
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = builder.build();
        http
                // http 통신에 대한 인가 정책 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/anonymous").hasRole("GUEST") // 인증된 사용자는 해당 자원 접근 불가능
                        .requestMatchers("/anonymous-context", "/authentication").permitAll()
                        .requestMatchers("/logout-success").permitAll()
                        .requestMatchers("/", "/api/login").permitAll()
                        .anyRequest().authenticated())
                // 인증 실패 시 인증 받도록 하는 방식 설정

                //.formLogin(Customizer.withDefaults()); // 폼 로그인 방식을 기본 default 방식으로 설정
//                .formLogin(form -> form
//                        //.loginPage("/loginPage")
//                        .loginProcessingUrl("/loginProc")
//                        // always use를 false 로 주면 인증 전에 가려고 했던 url로 리다이렉트
//                        .defaultSuccessUrl("/", true)
//                        .failureUrl("/failed")
//                        .usernameParameter("userId")
//                        .passwordParameter("pwd")
//                        .successHandler(new AuthenticationSuccessHandler() {
//                            @Override
//                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                                log.info("authentication : {}", authentication);
//                                // SavedRequest
//                                SavedRequest savedRequest = requestCache.getRequest(request, response);
//                                String redirectUrl = savedRequest.getRedirectUrl();
//                                log.info("### redirectUrl = {}", redirectUrl);
//                                response.sendRedirect(redirectUrl);
//                                //response.sendRedirect("/home");
//                            }
//                        })
//                        .failureHandler(new AuthenticationFailureHandler() {
//                            @Override
//                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                                log.info("exception {}", exception.getMessage());
//                                response.sendRedirect("/login");
//                            }
//                        })
//                        .permitAll()
//                )
                .authenticationManager(authenticationManager)
                // 커스텀 필터 추가
                .addFilterBefore(customAuthenticationFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .requestCache(cache -> cache.requestCache(requestCache))
                //.requestCache(cache -> cache.requestCache(new NullRequestCache()))
                // rememberMe 설정
                .rememberMe(r -> r
                        //.alwaysRemember(true) // default: false
                        .tokenValiditySeconds(3600) // 1시간
                        .userDetailsService(userDetailsService())
                        .rememberMeParameter("remember")
                        .rememberMeCookieName("remember")
                        .key("security")
                )
                // 익명 사용자 설정
                .anonymous(anonymous -> anonymous
                        .principal("guest") // default: anonymousUser
                        // 해당 권한을 가진 사용자만 접근할 수 있는 자원 설정 가능
                        .authorities("ROLE_GUEST") // default: ROLE_ANONYMOUS
                )
                .logout(logout -> logout
                        .logoutUrl("/logoutProc")
                        // logoutUrl 보다 우선순위 높음
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc", "POST"))
                        .logoutSuccessUrl("/logout-success")
                        .logoutSuccessHandler(new LogoutSuccessHandler() { // logoutSuccessUrl 보다 우선순위 높으며 좀더 복잡한 설정 가능
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/logout-success");
                            }
                        })
                        .deleteCookies("JSESSIONID", "remember", "remember-me") // 사실 JSESSIONID와 remember-me는 자동으로 삭제됨
                        .invalidateHttpSession(true) // 세션 무효화
                        .clearAuthentication(true) // Authentication 객체 삭제
                        .addLogoutHandler(new LogoutHandler() {
                            @Override
                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                HttpSession session = request.getSession();
                                session.invalidate();
                                // SecurityContext 안에 있는 Authentication 제거
                                SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
                                // SecurityContext 객체 클리어
                                SecurityContextHolder.getContextHolderStrategy().clearContext();
                            }
                        })
                        .permitAll() // /logoutProc URL 접근 가능 (logoutSuccessUrl, logoutSuccessHandler 에서 설정한 request는 컨트롤러에서 따로 만들어줘야 함)
                )
        ;
        return http.build();
    }

    public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
        customAuthenticationFilter.setAuthenticationManager(authenticationManager);

        return customAuthenticationFilter;
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
