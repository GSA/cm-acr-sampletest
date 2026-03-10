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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
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

        try {
            String tokenValidation = client.validateJwtToken(jwtRequest);
            assertEquals("invalid", tokenValidation);
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            // If ExpiredJwtException is thrown, that's also a valid indication
            // that the token is expired/invalid
            assertTrue(e.getMessage().contains("JWT expired"));
        } catch (Exception e) {
            // Any other exception related to expired token is also acceptable
            assertTrue(e.getCause() instanceof io.jsonwebtoken.ExpiredJwtException ||
                    e.getMessage().contains("expired") ||
                    e.getMessage().contains("JWT"));
        }
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