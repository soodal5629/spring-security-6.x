package io.security.springsecuritymaster;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AsyncService {
    @Async
    public void asyncMethod() {
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
        log.info("securityContext = {}", securityContext);
        log.info("Child Thread = {}", Thread.currentThread().getName());

    }
}
