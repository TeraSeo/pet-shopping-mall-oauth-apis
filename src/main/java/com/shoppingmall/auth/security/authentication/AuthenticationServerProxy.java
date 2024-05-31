package com.shoppingmall.auth.security.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class AuthenticationServerProxy {

    private final RestTemplate restTemplate;

    @Autowired
    public AuthenticationServerProxy(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void sendOtpRequest(String email) {

    }
    
    public boolean checkOtp(String email, String otp) {
        return true;
    }

}
