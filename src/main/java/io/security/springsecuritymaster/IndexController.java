package io.security.springsecuritymaster;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
public class IndexController {
    private final SessionInfoService sessionInfoService;
//    @GetMapping("/")
//    public String index(String customParam) {
//        log.info("### customParam ={}", customParam);
//        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
//        Authentication authentication = securityContext.getAuthentication();
//        log.info("### authentication ={}", authentication);
//        if (customParam != null) {
//            return "customPage";
//        } else {
//            return "index";
//        }
//    }

    @GetMapping("/")
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
}
