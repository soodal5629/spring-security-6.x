package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import java.util.concurrent.ConcurrentHashMap;

@Configuration
@EnableSpringHttpSession // JSESSIONID 가 아닌 SESSION 이름으로 세션 쿠키가 발급됨
public class HttpSessionConfig {
    @Bean
    // HttpSession 쿠키가 생성될때 해당 설정대로 생성됨
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
        cookieSerializer.setUseHttpOnlyCookie(true);
        cookieSerializer.setUseSecureCookie(true);
        cookieSerializer.setSameSite("Lax");
        return cookieSerializer;
    }

    @Bean
    // 세션을 저장할 저장소를 bean 등록
    public SessionRepository<MapSession> sessionRepository() {
        return new MapSessionRepository(new ConcurrentHashMap<>());
    }
}
