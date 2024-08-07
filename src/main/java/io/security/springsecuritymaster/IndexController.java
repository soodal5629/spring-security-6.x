package io.security.springsecuritymaster;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;

@RestController
@Slf4j
@RequiredArgsConstructor
public class IndexController {
    private final SessionInfoService sessionInfoService;
    private final AsyncService asyncService;

    // Authentication 익명 사용자 여부 확인 가능
    AuthenticationTrustResolverImpl trustResolver = new AuthenticationTrustResolverImpl();

    @GetMapping("/")
    public String index(String customParam) {
        log.info("### customParam ={}", customParam);
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
        Authentication authentication = securityContext.getAuthentication();
        log.info("### authentication ={}", authentication);
//        if (customParam != null) {
//            return "customPage";
//        } else {
//            return "index";
//        }
        return trustResolver.isAnonymous(authentication) ? "anonymous" : "authenticated";
    }

    @GetMapping("/index-authentication")
    public Authentication index(Authentication authentication) {
        return authentication;
    }

    @GetMapping("/sessionInfo")
    public String sessionInfo() {
        sessionInfoService.sessionInfo();
        return "sessionInfo";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/anonymous")
    public String anonymous() {
        return "anonymous";
    }

    @GetMapping("/authentication")
    public String authentication(Authentication authentication) {
        if (authentication instanceof AnonymousAuthenticationToken) {
            return "anonymous";
        } else {
            // 인증하지 않으면 Authentication 객체가 null이기 때문에 else 문으로 빠진다.
            return "not anonymous";
        }
    }

    @GetMapping("/anonymous-context")
    public String anonymousContext(@CurrentSecurityContext SecurityContext securityContext) {
        // 익명 객체 이름 리턴 가능
        return securityContext.getAuthentication().getName();
    }

    @GetMapping("/logout-success")
    public String logoutSuccess() {
        return "logout success";
    }

    @GetMapping("/invalidSessionUrl")
    public String invalidSessionUrl() {
        return "invalidSessionUrl";
    }

    @GetMapping("/expiredUrl")
    public String expiredUrl() {
        return "expiredUrl";
    }

    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }

    @GetMapping("/api/users")
    public String users() {
        return "{\"name\":\"hong gil dong\"}";
    }

    @PostMapping("/csrf")
    public String csrf() {
        return "csrf 적용됨";
    }

    @GetMapping("/csrfToken")
    public String csrfToken(HttpServletRequest request) {
        // csrfToken1,2 는 동일하게 HttpServletRequest에서 CsrfToken을 꺼냄
        CsrfToken csrfToken1 = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        CsrfToken csrfToken2 = (CsrfToken) request.getAttribute("_csrf");
        // csrfToken1,2 는 Supplier 로 감싸진 애들이기 때문에 getToken을 해야 인코딩된 토큰 값을 꺼낼 수 있다.
        String actualTokenValue = csrfToken1.getToken();

        return actualTokenValue;
    }

    @PostMapping("/formCsrf")
    public CsrfToken formCsrf(CsrfToken csrfToken) {
        return csrfToken;
    }

    @PostMapping("/cookieCsrf")
    public CsrfToken cookieCsrf(CsrfToken csrfToken) {
        return csrfToken;
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/user/{name}")
    public String userName(@PathVariable String name) {
        return name;
    }


    @GetMapping("/myPage/points")
    public String myPage() {
        return "myPage";
    }

    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/admin/payment")
    public String adminPayment() {
        return "adminPayment";
    }

    @GetMapping("/resource/address_01")
    public String address_01() {
        return "address_01";
    }

    @GetMapping("/resource/address01")
    public String address01() {
        return "address01";
    }

    @PostMapping("/post")
    public String post() {
        return "post";
    }

    @GetMapping("/admin/db")
    public String adminDb() {
        return "adminDB";
    }

    @GetMapping("/db")
    public String db() {
        return "db";
    }

    @GetMapping("/custom")
    public String custom() {
        return "custom";
    }

    @GetMapping("/api/photos")
    public String photos() {
        return "photos";
    }

    @GetMapping("/oauth/login")
    public String oauth() {
        return "oauthLogin";
    }

    @GetMapping("/secure")
    public String secure() {
        return "secure";
    }

    @GetMapping("/servlet-login")
    public String servletLogin(HttpServletRequest request, LoginDTO loginDTO) throws ServletException {
        // 필터가 아닌 서블릿을 통해 인증 및 로그인 처리
        request.login(loginDTO.getUsername(), loginDTO.getPassword());
        log.info("login is successful");
        return "login";
    }

    @GetMapping("/servlet-users")
    public List servletUsers(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // 서블릿 내 authenticate 메소드 사용
        boolean authenticated = request.authenticate(response);
        if(authenticated) {
            return List.of(new LoginDTO("user", "1111"));
        }
        return Collections.EMPTY_LIST;
    }

    @GetMapping("/annotation-user")
    // Authentication 내 User 객체 반환
    public User user(@AuthenticationPrincipal User user) {
        return user;
    }

    @GetMapping("/annotation-username")
    // Authentication -> User -> User 내 필드 username 바로 가져올 수 있음
    // 익명사용자일 경우 Principal이 'anonymousUser' 문자열로 들어가기 때문에 필드가 없으므로 에러 발생
    public String username(@AuthenticationPrincipal(expression = "username") String username) {
        return username;
    }

    @GetMapping("/annotation-currentuser")
    // @AuthenticationPrincipal 활용 커스텀 어노테이션
    public User currentUser(@CurrentUser User user) {
        return user;
    }

    @GetMapping("/annotation-currentusername")
    // @AuthenticationPrincipal 활용 커스텀 어노테이션
    public String currentUserName(@CurrentUsername String username) {
        return username;
    }

    @GetMapping("/callable")
    public Callable<Authentication> call() {
        // 메인/부모 스레드
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
        log.info("securityContext = {}", securityContext);
        log.info("Parent Thread = {}", Thread.currentThread().getName());

        // 자식 스레드
        // Callable은 별도의 스레드로 실행됨
        return new Callable<Authentication>() {
            @Override
            public Authentication call() throws Exception {
                SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
                log.info("securityContext = {}", securityContext);
                log.info("Child Thread = {}", Thread.currentThread().getName());
                return securityContext.getAuthentication();
            }
        };
    }

    @GetMapping("/async")
    public Authentication async() {
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
        log.info("securityContext = {}", securityContext);
        log.info("Parent Thread = {}", Thread.currentThread().getName());

        asyncService.asyncMethod();
        return securityContext.getAuthentication();
    }
}