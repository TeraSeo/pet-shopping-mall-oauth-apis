package com.shoppingmall.auth.security.filter;

import com.shoppingmall.auth.security.authentication.OtpAuthentication;
import com.shoppingmall.auth.security.authenticator.OtpAuthenticationProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class OtpAuthenticationFilter extends OncePerRequestFilter {

    private final OtpAuthenticationProvider otpAuthenticationProvider;
    private final Logger LOGGER = LoggerFactory.getLogger(OtpAuthenticationFilter.class);

    @Autowired
    public OtpAuthenticationFilter(OtpAuthenticationProvider otpAuthenticationProvider) {
        this.otpAuthenticationProvider = otpAuthenticationProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        LOGGER.debug("filter start");

        String email = request.getHeader("email");
        String code = request.getHeader("code");

        LOGGER.debug("email: " + email);
        LOGGER.debug("code: " + code);

        if (code != null) {
            Authentication a = new OtpAuthentication(email, code);
            otpAuthenticationProvider.authenticate(a);
        }

        filterChain.doFilter(request, response);
    }
}
