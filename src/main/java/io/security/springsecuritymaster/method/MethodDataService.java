package io.security.springsecuritymaster.method;

import io.security.springsecuritymaster.MethodAccountDTO;
import org.springframework.stereotype.Service;

@Service
public class MethodDataService {
    public String getUser() {
        return "user";
    }

    public MethodAccountDTO getOwner(String name) {
        return new MethodAccountDTO(name, false);
    }
}
