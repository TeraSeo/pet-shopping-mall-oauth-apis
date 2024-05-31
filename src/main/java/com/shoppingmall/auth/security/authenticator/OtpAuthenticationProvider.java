package com.shoppingmall.auth.security.authenticator;

import com.shoppingmall.auth.security.authentication.AuthenticationServerProxy;
import com.shoppingmall.auth.security.authentication.OtpAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class OtpAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationServerProxy authenticationServerProxy;

    @Autowired
    public OtpAuthenticationProvider(AuthenticationServerProxy authenticationServerProxy) {
        this.authenticationServerProxy = authenticationServerProxy;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String email = authentication.getName();
        String code = authentication.getCredentials().toString();

        boolean isCorrect = authenticationServerProxy.checkOtp(email, code);
        if (isCorrect) {
            return new OtpAuthentication(email, code);
        }
        throw new BadCredentialsException("Bad credentials");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthentication.class.isAssignableFrom(authentication);
    }
}
