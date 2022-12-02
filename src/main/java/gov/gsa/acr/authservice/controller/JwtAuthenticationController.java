package gov.gsa.acr.authservice.controller;

import gov.gsa.acr.authservice.config.JwtTokenUtil;
import gov.gsa.acr.authservice.model.JwtRequest;
import gov.gsa.acr.authservice.model.JwtResponse;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Date;
import java.util.Objects;

@RestController
@CrossOrigin
public class JwtAuthenticationController {

	Logger logger = LoggerFactory.getLogger(JwtAuthenticationController.class);
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private UserDetailsService jwtInMemoryUserDetailsService;


	@RequestMapping(value = "/liveliness", method = RequestMethod.GET)
	public String getLiveliness() {
		return "ALIVE";
	}

	@RequestMapping(value = "/readiness", method = RequestMethod.GET)
	public String getReadinessliness() {
		return "READY";
	}

	@RequestMapping(value = "/token", method = RequestMethod.POST)
	public ResponseEntity<JwtResponse> getToken(HttpServletRequest request, @RequestBody JwtRequest authenticationRequest)
			throws Exception {
		Authentication authentication =  authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword(), request);

		final String token = jwtTokenUtil.generateToken(authentication);
		logger.info("Loggedin User : "+authenticationRequest.getUsername()+ " for resource :"+request.getRequestURI()+
				" from ip address : "+request.getRemoteAddr()+" Host: " + request.getRemoteHost());

		return ResponseEntity.ok(new JwtResponse(token));
	}

	private Authentication authenticate(String username, String password, HttpServletRequest request) throws Exception {
		Objects.requireNonNull(username);
		Objects.requireNonNull(password);

		try {
			return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		}
		catch (BadCredentialsException e) {
			logger.error(" ***Login attempt FAILED***  User : "+username+ " Requested Resource :"+request.getRequestURI()+
					" IP address : "+request.getRemoteAddr()+" Host: " + request.getRemoteHost());
			throw e;
		}
	}	
	
	@RequestMapping(value = "/validation", method = RequestMethod.POST)
	public String validateJwtToken(@RequestBody JwtRequest tokenRequest)
			throws Exception {	
		
		String jwtToken = tokenRequest.getJwtToken();
		String tokenValidity = null;
		boolean isValid = jwtTokenUtil.validateToken(jwtToken);

		if(isValid) {
			tokenValidity = "valid";
		} else {
			tokenValidity = "invalid";
		}
		return tokenValidity;
	}
	
	@RequestMapping(value = "/ccp/validation", method = RequestMethod.POST)
	public String validateCCPToken(@RequestBody JwtRequest tokenRequest)
			throws Exception {	
		
		String jwtToken = tokenRequest.getJwtToken();
		String tokenValidity = "invalid";
		
		if(jwtTokenUtil.getUsernameFromToken(jwtToken) != null && 
				jwtTokenUtil.getUsernameFromToken(jwtToken).equalsIgnoreCase("ccp") && 
				jwtTokenUtil.validateToken(jwtToken)){			
			tokenValidity = "valid";
		}				
	
		return tokenValidity;
	}

	@RequestMapping(value = "/claims", method = RequestMethod.POST)
	public Claims claims(@RequestBody JwtRequest tokenRequest)
			throws Exception {

		String jwtToken = tokenRequest.getJwtToken();
		return jwtTokenUtil.getAllClaimsFromToken(jwtToken);
	}

	@RequestMapping(value = "/username", method = RequestMethod.POST)
	public String userName(@RequestBody JwtRequest tokenRequest)
			throws Exception {

		String jwtToken = tokenRequest.getJwtToken();
		return jwtTokenUtil.getUsernameFromToken(jwtToken);
	}


	@RequestMapping(value = "/expiration-date", method = RequestMethod.POST)
	public Date expirationDate(@RequestBody JwtRequest tokenRequest)
			throws Exception {

		String jwtToken = tokenRequest.getJwtToken();
		return jwtTokenUtil.getExpirationDateFromToken(jwtToken);
	}

	@RequestMapping(value = "/roles", method = RequestMethod.POST)
	public String[] roles(@RequestBody JwtRequest tokenRequest)
			throws Exception {
		String jwtToken = tokenRequest.getJwtToken();
		return jwtTokenUtil.getRoles(jwtToken);
	}
}
