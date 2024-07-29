package io.security.springsecuritymaster;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/method")
public class MethodAuthorizeController {
    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String admin() {
        return "admin";
    }
    @GetMapping("/user")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    public String user() {
        return "user";
    }
    @GetMapping("/isAuthenticated")
    @PreAuthorize("isAuthenticated")
    public String isAuthenticated() {
        return "isAuthenticated";
    }
    @GetMapping("/user/{id}")
    @PreAuthorize("#id == authentication.name")
    public String userAuthentication(@PathVariable String id) {
        return "user id";
    }

    @GetMapping("/owner")
    @PostAuthorize("returnObject.owner == authentication.name") // returnObject가 리턴하는 MethodAccountDTO를 가리킴
    public MethodAccountDTO owner(String name) {
        return new MethodAccountDTO(name, false);
    }
    @GetMapping("/isSecure")
    @PostAuthorize("hasAuthority('ROLE_ADMIN') and returnObject.isSecure()") // returnObject가 리턴하는 MethodAccountDTO를 가리킴
    public MethodAccountDTO isSecure(String name, String secure) {
        return new MethodAccountDTO(name, "Y".equals(secure));
    }
}
