package io.security.springsecuritymaster;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class IndexController {

    @GetMapping("/")
    public String index(String customParam) {
        log.info("### customParam ={}", customParam);
        if (customParam != null) {
            return "customPage";
        } else {
            return "index";
        }
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
    public String  logoutSuccess() {
        return "logout success";
    }
}
