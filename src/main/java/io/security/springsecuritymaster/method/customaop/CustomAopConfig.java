package io.security.springsecuritymaster.method.customaop;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * 직접 빈 등록한 AOP 기반 커스텀 인가 처리 구현
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = false)
public class CustomAopConfig {
    @Bean
    /**
     * 커스텀 MethodInterceptor - Advice 역할
     */
    public MethodInterceptor methodInterceptor() {
        AuthorizationManager<MethodInvocation> authorizationManager = AuthenticatedAuthorizationManager.authenticated();
        return new CustomMethodInterceptor(authorizationManager);
    }

    @Bean
    public Pointcut pointcut() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* io.security.springsecuritymaster.method.MethodDataService.*(..))");
        return pointcut;
    }

    /**
     * 커스텀 Advisor 빈 등록
     */
    @Bean
    public Advisor serviceAdvisor() {
        return new DefaultPointcutAdvisor(pointcut(), methodInterceptor());
    }
}
