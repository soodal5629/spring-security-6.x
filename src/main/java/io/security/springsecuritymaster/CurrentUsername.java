package io.security.springsecuritymaster;

import org.springframework.security.core.annotation.AuthenticationPrincipal;

import java.lang.annotation.*;

@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
// this는 AuthenticationPrincipal을 의미
// 익명사용자일 경우 기본적으로 Principal이 문자열 'anonymousUser' 로 들어가있기 때문에 username이라는 속성/필드가 없다.
@AuthenticationPrincipal(expression = "#this == 'anonymousUser'? null : username")
public @interface CurrentUsername {
}
