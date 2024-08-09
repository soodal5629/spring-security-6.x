package io.security.springsecuritymaster.customdsl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class MyCustomFilter extends OncePerRequestFilter {
    private boolean flag;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 파라미터로 전달된 HttpServletRequest는 Servlet 통합에서 배웠던 HttpServletRequest 에 보안 관련 메소드를 추가적으로 제공하는 래퍼(SecurityContextHolderAwareRequestWrapper)클래스이다.
        if(this.flag) {
            try {
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            request.login(username, password);
            } catch (Exception e) {
                log.info("인증 실패 {}", e);
            }
        }
        filterChain.doFilter(request, response);
    }

    public void setFlag(boolean flag) {
        this.flag = flag;
    }
}
