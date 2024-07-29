package io.security.springsecuritymaster;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/method")
@RequiredArgsConstructor
public class MethodAuthorizeController {
    private final DataService dataService;

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

    @PostMapping("/writeList")
    public List<MethodAccountDTO> writeList(@RequestBody List<MethodAccountDTO> data) {
        return dataService.writeList(data);
    }

    @PostMapping("/writeMap")
    public Map<String, MethodAccountDTO> writeMap(@RequestBody List<MethodAccountDTO> data) {
        Map<String, MethodAccountDTO> map = data.stream().collect(Collectors.toMap(e -> e.getOwner(), e -> e));
        return dataService.writeMap(map);
    }

    @GetMapping("/readList")
    public List<MethodAccountDTO> readList() {
        return dataService.readList();
    }

    @GetMapping("/readMap")
    public Map<String, MethodAccountDTO> readMap() {
        return dataService.readMap();
    }
}
