package io.security.springsecuritymaster;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class MethodAccountDTO {
    private String owner;
    private boolean isSecure;
}
