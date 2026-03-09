package gov.gsa.acr.authservice;

import gov.gsa.acr.authservice.controller.JwtAuthenticationController;
import gov.gsa.acr.authservice.model.JwtRequest;
import gov.gsa.acr.authservice.model.JwtResponse;
import gov.gsa.acr.authservice.service.JwtUserDetailsService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import java.util.ArrayList;


import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@SpringBootTest(properties = {
        "ACR_AUTH_JWT_SECRET=abcdefg",
        "ACR_AUTH_USER=fake_user",
        "ACR_AUTH_PASSWORD=$2a$10$oEb/eVKSKH5rWzSkZDFyXep0eU8ZENN/vvWS.56tRJEQ7ZHNrzsw.",
        "CCP_AUTH_USER=fake_user",
        "CCP_AUTH_PASSWORD=$2a$10$oEb/eVKSKH5rWzSkZDFyXep0eU8ZENN/vvWS.56tRJEQ7ZHNrzsw.",
        "CMO_AUTH_USER=fake_user",
        "CMO_AUTH_PASSWORD=$2a$10$oEb/eVKSKH5rWzSkZDFyXep0eU8ZENN/vvWS.56tRJEQ7ZHNrzsw.",
        "ADV_AUTH_USER=fake_user",
        "ADV_AUTH_PASSWORD=$2a$10$oEb/eVKSKH5rWzSkZDFyXep0eU8ZENN/vvWS.56tRJEQ7ZHNrzsw.",
        "ELIB_AUTH_USER=fake_user",
        "ELIB_AUTH_PASSWORD=$2a$10$oEb/eVKSKH5rWzSkZDFyXep0eU8ZENN/vvWS.56tRJEQ7ZHNrzsw.",
        "EBUY_AUTH_USER=fake_user",
        "EBUY_AUTH_PASSWORD=$2a$10$oEb/eVKSKH5rWzSkZDFyXep0eU8ZENN/vvWS.56tRJEQ7ZHNrzsw."}) // fake_password
class AuthServiceApplicationTests {

    @MockitoBean
    AuthenticationManager authenticationManager;

    @MockitoBean
    JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    JwtAuthenticationController client;

    @Value("${ACR_AUTH_JWT_SECRET}")
    String JWT_SECRET;

    @BeforeEach
    public void setUp() {
        // Mock the behavior of JwtUserDetailsService
        setupMockUserDetails();
    }
    private void setupMockUserDetails() {
        // Mock valid users
        String encodedPassword = "$2a$10$oEb/eVKSKH5rWzSkZDFyXep0eU8ZENN/vvWS.56tRJEQ7ZHNrzsw."; // fake_password

        UserDetails fakeUser = new User("fake_user", encodedPassword, new ArrayList<>());
        UserDetails acrUser = new User("acr", encodedPassword, new ArrayList<>());
        UserDetails ccpUser = new User("ccp", encodedPassword, new ArrayList<>());
        UserDetails cmoUser = new User("cmo", encodedPassword, new ArrayList<>());
        UserDetails advUser = new User("adv", encodedPassword, new ArrayList<>());
        UserDetails elibUser = new User("elib", encodedPassword, new ArrayList<>());
        UserDetails ebuyUser = new User("ebuy", encodedPassword, new ArrayList<>());

        // Configure mock behavior
        when(jwtUserDetailsService.loadUserByUsername("fake_user")).thenReturn(fakeUser);
        when(jwtUserDetailsService.loadUserByUsername("acr")).thenReturn(acrUser);
        when(jwtUserDetailsService.loadUserByUsername("ccp")).thenReturn(ccpUser);
        when(jwtUserDetailsService.loadUserByUsername("cmo")).thenReturn(cmoUser);
        when(jwtUserDetailsService.loadUserByUsername("adv")).thenReturn(advUser);
        when(jwtUserDetailsService.loadUserByUsername("elib")).thenReturn(elibUser);
        when(jwtUserDetailsService.loadUserByUsername("ebuy")).thenReturn(ebuyUser);

        // Mock invalid users to throw exception
        when(jwtUserDetailsService.loadUserByUsername("fake_user_that_does_not_exist"))
                .thenThrow(new UsernameNotFoundException("User not found"));
        when(jwtUserDetailsService.loadUserByUsername("fakse_user"))
                .thenThrow(new UsernameNotFoundException("User not found"));
        when(jwtUserDetailsService.loadUserByUsername("non_existent_user"))
                .thenThrow(new UsernameNotFoundException("User not found"));

        // Mock null and empty usernames
        when(jwtUserDetailsService.loadUserByUsername(null))
                .thenThrow(new UsernameNotFoundException("Username cannot be null"));
        when(jwtUserDetailsService.loadUserByUsername(""))
                .thenThrow(new UsernameNotFoundException("Username cannot be empty"));
    }



    @Test
    public void testValidCredential() throws Exception {
        String user = "fake_user";
        String pwd = "fake_password";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(user);
        jwtRequest.setPassword(pwd);
        MockHttpServletRequest request = new MockHttpServletRequest();

        ResponseEntity<JwtResponse> response = client.getToken(request, jwtRequest);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().getToken());

        JwtResponse jwtResponse = response.getBody();
        jwtRequest.setJwtToken(jwtResponse.getToken());
        String tokenValidation = client.validateJwtToken(jwtRequest);
        assertEquals("valid", tokenValidation);
    }

    @Test
    public void testExpiredJwt() throws Exception {
        Calendar yesterday = Calendar.getInstance();
        yesterday.add(Calendar.DAY_OF_MONTH, -1);

        String jwt = generateJwt("fake_user", yesterday);
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        // This should now handle the ExpiredJwtException gracefully
        String tokenValidation = client.validateJwtToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testInvalidCredential() throws Exception {
        String user = "fake_user_that_does_not_exist";
        String pwd = "invalid_password";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(user);
        jwtRequest.setPassword(pwd);
        MockHttpServletRequest request = new MockHttpServletRequest();

        try {
            client.getToken(request, jwtRequest);
            fail("Should have thrown exception for invalid credentials");
        } catch (Exception e) {
            assertEquals("User not found", e.getMessage());
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


    // User-Specific Token Validation Tests
    @Test
    public void testValidateACRToken() throws Exception {
        String jwt = generateJwtForUser("acr");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateACRToken(jwtRequest);
        assertEquals("valid", tokenValidation);
    }

    @Test
    public void testValidateCCPToken() throws Exception {
        String jwt = generateJwtForUser("ccp");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateCCPToken(jwtRequest);
        assertEquals("valid", tokenValidation);
    }

    @Test
    public void testValidateCMOToken() throws Exception {
        String jwt = generateJwtForUser("cmo");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateCMOToken(jwtRequest);
        assertEquals("valid", tokenValidation);
    }

    @Test
    public void testValidateADVToken() throws Exception {
        String jwt = generateJwtForUser("adv");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateAdvToken(jwtRequest);
        assertEquals("valid", tokenValidation);
    }

    @Test
    public void testValidateElibToken() throws Exception {
        String jwt = generateJwtForUser("elib");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateElibToken(jwtRequest);
        assertEquals("valid", tokenValidation);
    }

    @Test
    public void testValidateEbuyToken() throws Exception {
        String jwt = generateJwtForUser("ebuy");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateEbuyToken(jwtRequest);
        assertEquals("valid", tokenValidation);
    }

    // Cross-User Token Validation Tests (Security)
    @Test
    public void testACRTokenInvalidForCCP() throws Exception {
        String jwt = generateJwtForUser("acr");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateCCPToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testCCPTokenInvalidForCMO() throws Exception {
        String jwt = generateJwtForUser("ccp");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateCMOToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testCMOTokenInvalidForACR() throws Exception {
        String jwt = generateJwtForUser("cmo");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateACRToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testElibTokenInvalidForEbuy() throws Exception {
        String jwt = generateJwtForUser("elib");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateEbuyToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    // Health Check Test
    @Test
    public void testLivelinessEndpoint() throws Exception {
        String response = client.getLiveliness();
        assertEquals("ALIVE", response);
    }

    // Malformed Token Tests
    /*
    @Test
    public void testMalformedToken() throws Exception {
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken("invalid.jwt.token");

        String tokenValidation = client.validateJwtToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testNullToken() throws Exception {
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(null);

        String tokenValidation = client.validateJwtToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testEmptyToken() throws Exception {
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken("");

        String tokenValidation = client.validateJwtToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testTokenWithSpecialCharacters() throws Exception {
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken("@#$%^&*()");

        String tokenValidation = client.validateJwtToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    // Wrong Signature Tests
    @Test
    public void testTokenWithWrongSignature() throws Exception {
        String jwt = generateJwtWithWrongSecret("acr");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateACRToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testCCPTokenWithWrongSignature() throws Exception {
        String jwt = generateJwtWithWrongSecret("ccp");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateCCPToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    // Authentication Edge Cases
    @Test
    public void testValidCredentialsButWrongUser() throws Exception {
        String user = "non_existent_user";
        String pwd = "fake_password";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(user);
        jwtRequest.setPassword(pwd);
        MockHttpServletRequest request = new MockHttpServletRequest();

        try {
            client.getToken(request, jwtRequest);
            fail("Should have thrown exception for non-existent user");
        } catch (Exception e) {
            assertEquals("INVALID_CREDENTIALS", e.getMessage());
        }
    }

    @Test
    public void testNullUsername() throws Exception {
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(null);
        jwtRequest.setPassword("fake_password");
        MockHttpServletRequest request = new MockHttpServletRequest();

        try {
            client.getToken(request, jwtRequest);
            fail("Should have thrown exception for null username");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("INVALID_CREDENTIALS") ||
                    e.getMessage().contains("USER_DISABLED"));
        }
    }

    @Test
    public void testNullPassword() throws Exception {
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername("fake_user");
        jwtRequest.setPassword(null);
        MockHttpServletRequest request = new MockHttpServletRequest();

        try {
            client.getToken(request, jwtRequest);
            fail("Should have thrown exception for null password");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("INVALID_CREDENTIALS") ||
                    e.getMessage().contains("USER_DISABLED"));
        }
    }

    @Test
    public void testEmptyUsername() throws Exception {
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername("");
        jwtRequest.setPassword("fake_password");
        MockHttpServletRequest request = new MockHttpServletRequest();

        try {
            client.getToken(request, jwtRequest);
            fail("Should have thrown exception for empty username");
        } catch (Exception e) {
            assertEquals("INVALID_CREDENTIALS", e.getMessage());
        }
    }

    @Test
    public void testEmptyPassword() throws Exception {
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername("fake_user");
        jwtRequest.setPassword("");
        MockHttpServletRequest request = new MockHttpServletRequest();

        try {
            client.getToken(request, jwtRequest);
            fail("Should have thrown exception for empty password");
        } catch (Exception e) {
            assertEquals("INVALID_CREDENTIALS", e.getMessage());
        }
    }

    // Expired Token Tests for All Users
    @Test
    public void testExpiredACRToken() throws Exception {
        Calendar yesterday = Calendar.getInstance();
        yesterday.add(Calendar.DAY_OF_MONTH, -1);

        String jwt = generateJwtForUserWithExpiry("acr", yesterday);
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateACRToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testExpiredCCPToken() throws Exception {
        Calendar yesterday = Calendar.getInstance();
        yesterday.add(Calendar.DAY_OF_MONTH, -1);

        String jwt = generateJwtForUserWithExpiry("ccp", yesterday);
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateCCPToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testExpiredCMOToken() throws Exception {
        Calendar yesterday = Calendar.getInstance();
        yesterday.add(Calendar.DAY_OF_MONTH, -1);

        String jwt = generateJwtForUserWithExpiry("cmo", yesterday);
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateCMOToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    // Token Case Sensitivity Tests
    @Test
    public void testACRTokenCaseSensitive() throws Exception {
        String jwt = generateJwtForUser("ACR"); // uppercase
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateACRToken(jwtRequest);
        assertEquals("invalid", tokenValidation); // should be invalid due to case sensitivity
    }

    @Test
    public void testCCPTokenCaseSensitive() throws Exception {
        String jwt = generateJwtForUser("CCP"); // uppercase
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateCCPToken(jwtRequest);
        assertEquals("invalid", tokenValidation); // should be invalid due to case sensitivity
    }

    // Password Encoding Tests
    @Test
    public void testMultiplePasswordEncodings() throws Exception {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String clearPassword = "test_password_123";

        // Test multiple encodings of same password
        String encoded1 = passwordEncoder.encode(clearPassword);
        String encoded2 = passwordEncoder.encode(clearPassword);
        String encoded3 = passwordEncoder.encode(clearPassword);

        // Each encoding should be different (due to salt)
        assertTrue(!encoded1.equals(encoded2));
        assertTrue(!encoded2.equals(encoded3));
        assertTrue(!encoded1.equals(encoded3));

        // But all should match the original password
        assertTrue(passwordEncoder.matches(clearPassword, encoded1));
        assertTrue(passwordEncoder.matches(clearPassword, encoded2));
        assertTrue(passwordEncoder.matches(clearPassword, encoded3));
    }

    @Test
    public void testPasswordEncodingWithSpecialCharacters() throws Exception {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String specialPassword = "P@ssw0rd!@#$%^&*()";
        String encoded = passwordEncoder.encode(specialPassword);

        assertTrue(passwordEncoder.matches(specialPassword, encoded));
        // Test wrong password
        assertTrue(!passwordEncoder.matches("wrongpassword", encoded));
    }

    @Test
    public void testPasswordEncodingWithEmptyPassword() throws Exception {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String emptyPassword = "";
        String encoded = passwordEncoder.encode(emptyPassword);

        assertTrue(passwordEncoder.matches(emptyPassword, encoded));
    }

    // Token Future Date Tests
    @Test
    public void testFutureExpirationToken() throws Exception {
        Calendar nextYear = Calendar.getInstance();
        nextYear.add(Calendar.YEAR, 1);

        String jwt = generateJwtForUserWithExpiry("acr", nextYear);
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateACRToken(jwtRequest);
        assertEquals("valid", tokenValidation);
    }

    @Test
    public void testTokenExpiringInOneMinute() throws Exception {
        Calendar oneMinute = Calendar.getInstance();
        oneMinute.add(Calendar.MINUTE, 1);

        String jwt = generateJwtForUserWithExpiry("ccp", oneMinute);
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        String tokenValidation = client.validateCCPToken(jwtRequest);
        assertEquals("valid", tokenValidation);
    }

    // Boundary Tests
    @Test
    public void testTokenExpiringAtExactCurrentTime() throws Exception {
        Calendar now = Calendar.getInstance();

        String jwt = generateJwtForUserWithExpiry("cmo", now);
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        // This might be valid or invalid depending on exact timing
        String tokenValidation = client.validateCMOToken(jwtRequest);
        assertTrue("valid".equals(tokenValidation) || "invalid".equals(tokenValidation));
    }

    // Multiple Validation Attempts Tests
    @Test
    public void testMultipleValidationSameToken() throws Exception {
        String jwt = generateJwtForUser("acr");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        // Multiple calls should return same result
        String validation1 = client.validateACRToken(jwtRequest);
        String validation2 = client.validateACRToken(jwtRequest);
        String validation3 = client.validateACRToken(jwtRequest);

        assertEquals("valid", validation1);
        assertEquals("valid", validation2);
        assertEquals("valid", validation3);
    }

    @Test
    public void testValidationWithDifferentTokens() throws Exception {
        String jwt1 = generateJwtForUser("acr");
        String jwt2 = generateJwtForUser("acr");

        JwtRequest jwtRequest1 = new JwtRequest();
        jwtRequest1.setJwtToken(jwt1);

        JwtRequest jwtRequest2 = new JwtRequest();
        jwtRequest2.setJwtToken(jwt2);

        String validation1 = client.validateACRToken(jwtRequest1);
        String validation2 = client.validateACRToken(jwtRequest2);

        assertEquals("valid", validation1);
        assertEquals("valid", validation2);
    }

    // Token Content Manipulation Tests
    @Test
    public void testTamperedTokenPayload() throws Exception {
        String validJwt = generateJwtForUser("acr");
        // Tamper with the token by changing one character in the middle (payload section)
        String tamperedJwt = validJwt.substring(0, validJwt.length()/2) + "X" + validJwt.substring(validJwt.length()/2 + 1);

        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(tamperedJwt);

        String tokenValidation = client.validateACRToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    @Test
    public void testTruncatedToken() throws Exception {
        String validJwt = generateJwtForUser("ccp");
        // Truncate the token
        String truncatedJwt = validJwt.substring(0, validJwt.length() - 10);

        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(truncatedJwt);

        String tokenValidation = client.validateCCPToken(jwtRequest);
        assertEquals("invalid", tokenValidation);
    }

    // Performance/Load Tests
    @Test
    public void testValidationPerformance() throws Exception {
        String jwt = generateJwtForUser("acr");
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(jwt);

        long startTime = System.currentTimeMillis();

        // Perform 100 validations
        for (int i = 0; i < 100; i++) {
            String validation = client.validateACRToken(jwtRequest);
            assertEquals("valid", validation);
        }

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        // Should complete within reasonable time (adjust threshold as needed)
        assertTrue(duration < 5000, "100 validations took too long: " + duration + "ms");
    }

    // Authentication Response Tests
    @Test
    public void testAuthenticationResponseStructure() throws Exception {
        String user = "fake_user";
        String pwd = "fake_password";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(user);
        jwtRequest.setPassword(pwd);
        MockHttpServletRequest request = new MockHttpServletRequest();

        ResponseEntity<JwtResponse> response = client.getToken(request, jwtRequest);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() != null);
        assertTrue(response.getBody().getToken() != null);
        assertTrue(!response.getBody().getToken().isEmpty());
    }

    @Test
    public void testTokenFormatValidation() throws Exception {
        String user = "fake_user";
        String pwd = "fake_password";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setUsername(user);
        jwtRequest.setPassword(pwd);
        MockHttpServletRequest request = new MockHttpServletRequest();

        ResponseEntity<JwtResponse> response = client.getToken(request, jwtRequest);
        String token = response.getBody().getToken();

        // JWT should have 3 parts separated by dots
        String[] parts = token.split("\\.");
        assertEquals(3, parts.length, "JWT should have 3 parts separated by dots");

        // Each part should not be empty
        assertTrue(parts[0].length() > 0, "Header should not be empty");
        assertTrue(parts[1].length() > 0, "Payload should not be empty");
        assertTrue(parts[2].length() > 0, "Signature should not be empty");
    }

    // All Users Invalid Token Tests
    @Test
    public void testInvalidTokenForAllUsers() throws Exception {
        String invalidToken = "invalid.token.here";
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setJwtToken(invalidToken);

        assertEquals("invalid", client.validateACRToken(jwtRequest));
        assertEquals("invalid", client.validateCCPToken(jwtRequest));
        assertEquals("invalid", client.validateCMOToken(jwtRequest));
        assertEquals("invalid", client.validateAdvToken(jwtRequest));
        assertEquals("invalid", client.validateElibToken(jwtRequest));
        assertEquals("invalid", client.validateEbuyToken(jwtRequest));
    }

    @Test
    public void testExpiredTokenForAllUsers() throws Exception {
        Calendar yesterday = Calendar.getInstance();
        yesterday.add(Calendar.DAY_OF_MONTH, -1);

        JwtRequest jwtRequest = new JwtRequest();

        // Test expired token for each user type
        jwtRequest.setJwtToken(generateJwtForUserWithExpiry("acr", yesterday));
        assertEquals("invalid", client.validateACRToken(jwtRequest));

        jwtRequest.setJwtToken(generateJwtForUserWithExpiry("ccp", yesterday));
        assertEquals("invalid", client.validateCCPToken(jwtRequest));

        jwtRequest.setJwtToken(generateJwtForUserWithExpiry("cmo", yesterday));
        assertEquals("invalid", client.validateCMOToken(jwtRequest));

        jwtRequest.setJwtToken(generateJwtForUserWithExpiry("adv", yesterday));
        assertEquals("invalid", client.validateAdvToken(jwtRequest));

        jwtRequest.setJwtToken(generateJwtForUserWithExpiry("elib", yesterday));
        assertEquals("invalid", client.validateElibToken(jwtRequest));

        jwtRequest.setJwtToken(generateJwtForUserWithExpiry("ebuy", yesterday));
        assertEquals("invalid", client.validateEbuyToken(jwtRequest));
    }
    */
    // ========== HELPER METHODS ==========

    private String generateJwt(String subject, Calendar expireDate) {
        Date expiryDate = expireDate.getTime();
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .compact();
    }

    private String generateJwtForUser(String username) {
        Calendar futureDate = Calendar.getInstance();
        futureDate.add(Calendar.HOUR, 10); // 10 hours from now
        return generateJwtForUserWithExpiry(username, futureDate);
    }

    private String generateJwtForUserWithExpiry(String username, Calendar expireDate) {
        Date expiryDate = expireDate.getTime();
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .compact();
    }

    private String generateJwtWithWrongSecret(String username) {
        Calendar futureDate = Calendar.getInstance();
        futureDate.add(Calendar.HOUR, 10);
        Date expiryDate = futureDate.getTime();
        Map<String, Object> claims = new HashMap<>();

        // Use wrong secret for signing
        String wrongSecret = "wrongsecret123";
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, wrongSecret)
                .compact();
    }

    private String createToken(Map<String, Object> claims, String subject) {
        Calendar futureDate = Calendar.getInstance();
        futureDate.add(Calendar.HOUR, 10);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(futureDate.getTime())
                .signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .compact();
    }


}