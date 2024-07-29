package io.security.springsecuritymaster;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.*;

/**
* 커스텀 메타 주석
* */
@Documented
@Retention(RUNTIME)
@Target({TYPE, METHOD})
@PreAuthorize("hasRole('ADMIN')")
public @interface IsAdmin {
}
