package gov.gsa.acr.authservice;

import gov.gsa.acr.authservice.controller.JwtAuthenticationController;
import gov.gsa.acr.authservice.model.JwtRequest;
import gov.gsa.acr.authservice.model.JwtResponse;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import java.util.Calendar;

@SpringBootTest(properties = {
        "ACR_AUTH_JWT_SECRET=acr123",
        "ACR_AUTH_USER=acr",
        "ACR_AUTH_PASSWORD=$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6"}) // fake_password
class AuthServiceApplicationTests {

    @Autowired
    JwtAuthenticationController client;

    @Value("${ACR_AUTH_JWT_SECRET}")
    String JWT_SECRET;

    @Test
    public void testValidCredential() throws Exception {
        String user = "fake_user";
        String pwd = "fake_password";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(user);
        jwtRequest.setPassword(pwd);
        MockHttpServletRequest request = new MockHttpServletRequest();

        ResponseEntity<JwtResponse> response = client.getToken(request, jwtRequest);
        assertEquals(response.getStatusCode(), HttpStatus.OK);

        JwtResponse jwtResponse = response.getBody();
        jwtRequest.setJwtToken(jwtResponse.getToken());
        String tokenValidation = client.validateJwtToken(jwtRequest);
        assertEquals(tokenValidation, "valid");
    }

    @Test
    public void testExpiredJwt() throws Exception {
        Calendar yesterday = Calendar.getInstance();
        yesterday.add(Calendar.DAY_OF_MONTH,  -1);

        String jwt = generateJwt("fake", yesterday);
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);
        String tokenValidation = client.validateJwtToken(jwtRequest);
        assertEquals(tokenValidation, "invalid");
    }

    @Test
    public void testInvalidCredential() throws Exception {
        String user = "fakse_user";
        String pwd = "invalid_password";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(user);
        jwtRequest.setPassword(pwd);

        MockHttpServletRequest request = new MockHttpServletRequest();

        try {
            // bad credentials - should throw exception
            client.getToken(request, jwtRequest);
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

    private String generateJwt(String subject, Calendar expireDate) {
        Date expiryDate = expireDate.getTime();
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expiryDate/*new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY*1000)*/).signWith(SignatureAlgorithm.HS512, JWT_SECRET).compact();
    }

}
