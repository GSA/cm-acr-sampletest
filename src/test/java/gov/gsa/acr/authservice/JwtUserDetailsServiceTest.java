package gov.gsa.acr.authservice;

import gov.gsa.acr.authservice.service.JwtUserDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class JwtUserDetailsServiceTest {

    private JwtUserDetailsService jwtUserDetailsService;

    // Test data constants
    private static final String ACR_USER = "acrUser";
    private static final String ACR_PASSWORD = "acrPassword123";
    private static final String CCP_USER = "ccpUser";
    private static final String CCP_PASSWORD = "ccpPassword123";
    private static final String CMO_USER = "cmoUser";
    private static final String CMO_PASSWORD = "cmoPassword123";
    private static final String ADV_USER = "advUser";
    private static final String ADV_PASSWORD = "advPassword123";
    private static final String ELIB_USER = "elibUser";
    private static final String ELIB_PASSWORD = "elibPassword123";
    private static final String EBUY_USER = "ebuyUser";
    private static final String EBUY_PASSWORD = "ebuyPassword123";

    @BeforeEach
    void setUp() {
        jwtUserDetailsService = new JwtUserDetailsService();

        // Set up the @Value fields using ReflectionTestUtils
        ReflectionTestUtils.setField(jwtUserDetailsService, "user", ACR_USER);
        ReflectionTestUtils.setField(jwtUserDetailsService, "password", ACR_PASSWORD);
        ReflectionTestUtils.setField(jwtUserDetailsService, "ccpUser", CCP_USER);
        ReflectionTestUtils.setField(jwtUserDetailsService, "ccpPassword", CCP_PASSWORD);
        ReflectionTestUtils.setField(jwtUserDetailsService, "cmoUser", CMO_USER);
        ReflectionTestUtils.setField(jwtUserDetailsService, "cmoPassword", CMO_PASSWORD);
        ReflectionTestUtils.setField(jwtUserDetailsService, "advUser", ADV_USER);
        ReflectionTestUtils.setField(jwtUserDetailsService, "advPassword", ADV_PASSWORD);
        ReflectionTestUtils.setField(jwtUserDetailsService, "elibUser", ELIB_USER);
        ReflectionTestUtils.setField(jwtUserDetailsService, "elibPassword", ELIB_PASSWORD);
        ReflectionTestUtils.setField(jwtUserDetailsService, "ebuyUser", EBUY_USER);
        ReflectionTestUtils.setField(jwtUserDetailsService, "ebuyPassword", EBUY_PASSWORD);
    }

    @Test
    void loadUserByUsername_ShouldReturnAcrUser_WhenUsernameMatchesAcrUser() {
        // Act
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(ACR_USER);

        // Assert
        assertNotNull(userDetails);
        assertEquals(ACR_USER, userDetails.getUsername());
        assertEquals(ACR_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    @Test
    void loadUserByUsername_ShouldReturnAcrUser_WhenUsernameMatchesAcrUserIgnoreCase() {
        // Act
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(ACR_USER.toUpperCase());

        // Assert
        assertNotNull(userDetails);
        assertEquals(ACR_USER, userDetails.getUsername());
        assertEquals(ACR_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    @Test
    void loadUserByUsername_ShouldReturnCcpUser_WhenUsernameMatchesCcpUser() {
        // Act
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(CCP_USER);

        // Assert
        assertNotNull(userDetails);
        assertEquals(CCP_USER, userDetails.getUsername());
        assertEquals(CCP_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    @Test
    void loadUserByUsername_ShouldReturnCcpUser_WhenUsernameMatchesCcpUserIgnoreCase() {
        // Act
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(CCP_USER.toUpperCase());

        // Assert
        assertNotNull(userDetails);
        assertEquals(CCP_USER, userDetails.getUsername());
        assertEquals(CCP_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    @Test
    void loadUserByUsername_ShouldReturnCmoUser_WhenUsernameMatchesCmoUser() {
        // Act
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(CMO_USER);

        // Assert
        assertNotNull(userDetails);
        assertEquals(CMO_USER, userDetails.getUsername());
        assertEquals(CMO_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    @Test
    void loadUserByUsername_ShouldReturnAdvUser_WhenUsernameMatchesAdvUser() {
        // Act
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(ADV_USER);

        // Assert
        assertNotNull(userDetails);
        assertEquals(ADV_USER, userDetails.getUsername());
        assertEquals(ADV_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    @Test
    void loadUserByUsername_ShouldReturnElibUser_WhenUsernameMatchesElibUser() {
        // Act
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(ELIB_USER);

        // Assert
        assertNotNull(userDetails);
        assertEquals(ELIB_USER, userDetails.getUsername());
        assertEquals(ELIB_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    @Test
    void loadUserByUsername_ShouldReturnEbuyUser_WhenUsernameMatchesEbuyUser() {
        // Act
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(EBUY_USER);

        // Assert
        assertNotNull(userDetails);
        assertEquals(EBUY_USER, userDetails.getUsername());
        assertEquals(EBUY_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    @Test
    void loadUserByUsername_ShouldThrowUsernameNotFoundException_WhenUsernameDoesNotMatch() {
        // Arrange
        String unknownUsername = "unknownUser";

        // Act & Assert
        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> jwtUserDetailsService.loadUserByUsername(unknownUsername)
        );

        assertEquals("User not found with username : " + unknownUsername, exception.getMessage());
    }

    @Test
    void loadUserByUsername_ShouldThrowUsernameNotFoundException_WhenUsernameIsNull() {
        // Act & Assert
        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> jwtUserDetailsService.loadUserByUsername(null)
        );

        assertEquals("User not found with username : null", exception.getMessage());
    }

    @Test
    void loadUserByUsername_ShouldThrowUsernameNotFoundException_WhenUsernameIsEmpty() {
        // Act & Assert
        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> jwtUserDetailsService.loadUserByUsername("")
        );

        assertEquals("User not found with username : ", exception.getMessage());
    }

    @Test
    void loadUserByUsername_ShouldThrowUsernameNotFoundException_WhenUsernameIsWhitespace() {
        // Arrange
        String whitespaceUsername = "   ";

        // Act & Assert
        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> jwtUserDetailsService.loadUserByUsername(whitespaceUsername)
        );

        assertEquals("User not found with username : " + whitespaceUsername, exception.getMessage());
    }

    @Test
    void loadUserByUsername_ShouldReturnUserWithEmptyAuthorities_ForAllValidUsers() {
        // Test that all valid users return empty authorities
        String[] validUsers = {ACR_USER, CCP_USER, CMO_USER, ADV_USER, ELIB_USER, EBUY_USER};

        for (String username : validUsers) {
            UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);
            assertNotNull(userDetails.getAuthorities());
            assertTrue(userDetails.getAuthorities().isEmpty(),
                    "Authorities should be empty for user: " + username);
        }
    }

    @Test
    void loadUserByUsername_ShouldBeCaseInsensitive_ForAllValidUsers() {
        // Test case insensitivity for all users
        String[] validUsers = {ACR_USER, CCP_USER, CMO_USER, ADV_USER, ELIB_USER, EBUY_USER};

        for (String username : validUsers) {
            // Test with uppercase
            UserDetails upperCaseResult = jwtUserDetailsService.loadUserByUsername(username.toUpperCase());
            assertNotNull(upperCaseResult);
            assertEquals(username, upperCaseResult.getUsername());

            // Test with lowercase
            UserDetails lowerCaseResult = jwtUserDetailsService.loadUserByUsername(username.toLowerCase());
            assertNotNull(lowerCaseResult);
            assertEquals(username, lowerCaseResult.getUsername());
        }
    }

    @Test
    void loadUserByUsername_ShouldHandlePartialMatches_AsInvalidUsers() {
        // Test that partial matches are treated as invalid
        String partialMatch = ACR_USER.substring(0, ACR_USER.length() - 1);

        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> jwtUserDetailsService.loadUserByUsername(partialMatch)
        );

        assertEquals("User not found with username : " + partialMatch, exception.getMessage());
    }
}