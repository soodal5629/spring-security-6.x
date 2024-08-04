package io.security.springsecuritymaster.method.customaop;

import lombok.RequiredArgsConstructor;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.file.AccessDeniedException;

/**
 * 커스텀 MethodInterceptor(Advice)
 */
@RequiredArgsConstructor
public class CustomMethodInterceptor implements MethodInterceptor {
    private final AuthorizationManager<MethodInvocation> authorizationManager;

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // check 메소드의 파라미터 authentication 은 Supplier로 감싸서 전달해야 함(Authentication 그대로 보내면 안됨)
        if(authorizationManager.check(() -> authentication, invocation).isGranted()) {
            return invocation.proceed();
        }
            throw new AccessDeniedException("Access Denied !!");
    }
}
