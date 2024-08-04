package io.security.springsecuritymaster.method;

import io.security.springsecuritymaster.MethodAccountDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/method/custom")
@RequiredArgsConstructor
public class CustomMethodController {
    private final MethodDataService methodDataService;
    @GetMapping("/admin")
    @PreAuthorize(value = "")
    public String admin() {
        return "admin";
    }
    @GetMapping("/user")
    @PostAuthorize(value = "isAuthenticated()")
    public MethodAccountDTO user(String name) {
        return new MethodAccountDTO(name, false);
    }

    @GetMapping("/pointcut/admin")
    public String pointcutAdmin() {
        return methodDataService.getUser();
    }
    @GetMapping("/pointcut/user")
    public MethodAccountDTO pointcutUser(String name) {
        return methodDataService.getOwner(name);
    }

}
