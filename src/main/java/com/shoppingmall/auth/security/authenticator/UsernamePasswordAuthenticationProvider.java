package com.shoppingmall.auth.security.authenticator;

import com.shoppingmall.auth.entity.User;
import com.shoppingmall.auth.repository.UserRepository;
import com.shoppingmall.auth.security.authentication.AuthenticationServerProxy;
import com.shoppingmall.auth.security.authentication.UsernamePasswordAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationServerProxy authenticationServerProxy;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public UsernamePasswordAuthenticationProvider(AuthenticationServerProxy authenticationServerProxy, UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.authenticationServerProxy = authenticationServerProxy;
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String email = authentication.getName();
        String password = authentication.getCredentials().toString();

        checkPassword(email, password);
        throw new BadCredentialsException("Bad credentials");
    }

    private UsernamePasswordAuthentication checkPassword(String email, String password) {

        Optional<User> u = userRepository.findByEmail(email);
        if (u.isPresent()) {
            User user = u.get();
            if (bCryptPasswordEncoder.matches(password, user.getPassword())) {
                authenticationServerProxy.sendOtpRequest(email);
                return new UsernamePasswordAuthentication(email, user.getPassword());
            }
        }
        throw new BadCredentialsException("Bad credentials");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthentication.class.isAssignableFrom(authentication);
    }
}
