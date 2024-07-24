package io.security.springsecuritymaster;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;

import java.util.function.Supplier;

/*
* Single Page Application 에서 csrf 토큰 다루는 방법 (커스텀하게 로직 구현)
* 쿠키 이용하여 csrf 토큰 생성/인코딩 및 js에서 넘겨준 csrf 토큰 검증
* */
public class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {
    private final CsrfTokenRequestAttributeHandler delegate = new XorCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> deferredCsrfToken) {
        delegate.handle(request, response, deferredCsrfToken);
    }

    // Custom Logic
    // 1. 리퀘스트 헤더에 csrf 토큰이 넘어오는 것은 인코딩 되어 있지 않다고 가정하여 원본 값과 바로 비교
    // 2. 헤더에 담겨있지 않다면 인코딩된 csrf 토큰이라고 간주하여 디코딩하고 원본 값과 비교
    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
        if (StringUtils.hasText(request.getHeader(csrfToken.getHeaderName()))) {
            return super.resolveCsrfTokenValue(request, csrfToken);
        }
        return delegate.resolveCsrfTokenValue(request, csrfToken);
    }
}
