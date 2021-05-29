package gov.gsa.acr.authservice;

import gov.gsa.acr.authservice.controller.JwtAuthenticationController;
import gov.gsa.acr.authservice.model.JwtRequest;
import gov.gsa.acr.authservice.model.JwtResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(properties = { 
    "ACR_AUTH_JWT_SECRET=abcdefg",
    "ACR_AUTH_USER=fake_user",
    "ACR_AUTH_PASSWORD=$2a$10$oEb/eVKSKH5rWzSkZDFyXep0eU8ZENN/vvWS.56tRJEQ7ZHNrzsw."}) // fake_password
class AuthServiceApplicationTests {

    @Autowired
    JwtAuthenticationController client;

    @Test
    public void testValidCredential() throws Exception {
        String user = "fake_user";
        String pwd = "fake_password";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(user);
        jwtRequest.setPassword(pwd);

        ResponseEntity<JwtResponse> response = (ResponseEntity<JwtResponse>) client.getToken(jwtRequest);
        assertEquals(response.getStatusCode(), HttpStatus.OK);

        JwtResponse jwtResponse = response.getBody();
        jwtRequest.setJwtToken(jwtResponse.getToken());
        String tokenValidation = client.validateJwtToken(jwtRequest);
        assertEquals(tokenValidation, "valid");
    }

    @Test
    public void testInvalidCredential() throws Exception {
        String user = "fakse_user";
        String pwd = "invalid_password";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(user);
        jwtRequest.setPassword(pwd);
        try {
            ResponseEntity response = client.getToken(jwtRequest);
        }
        catch (Exception e) {
            assertEquals(e.getMessage(), "INVALID_CREDENTIALS");
        }
    }

    @Test
    public void generateEncryptedPassword() throws Exception {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String clearPassword = "fake_password";
        String encruptedPassword = passwordEncoder.encode(clearPassword);
        System.out.println(encruptedPassword);
        assertTrue(passwordEncoder.matches(clearPassword, encruptedPassword));
    }
}
