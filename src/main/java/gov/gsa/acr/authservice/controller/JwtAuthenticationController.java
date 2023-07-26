package gov.gsa.acr.authservice.controller;

import java.util.Objects;

//import javax.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import gov.gsa.acr.authservice.config.JwtTokenUtil;
import gov.gsa.acr.authservice.model.JwtRequest;
import gov.gsa.acr.authservice.model.JwtResponse;

@RestController
@CrossOrigin
public class JwtAuthenticationController {

	Logger logger = LoggerFactory.getLogger(JwtAuthenticationController.class);

	private static String ACR_USER = "acr";
	private static String CCP_USER = "ccp";
	private static String CMO_USER = "cmo";


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
		authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword(), request);		
		 
		final UserDetails userDetails = jwtInMemoryUserDetailsService
				.loadUserByUsername(authenticationRequest.getUsername());

		final String token = jwtTokenUtil.generateToken(userDetails);
		
		logger.info("Loggedin User : "+authenticationRequest.getUsername()+ " for resource :"+request.getRequestURI()+
				" from ip address : "+request.getRemoteAddr()+" Host: " + request.getRemoteHost());

		return ResponseEntity.ok(new JwtResponse(token));
	}

	private void authenticate(String username, String password, HttpServletRequest request) throws Exception {
		Objects.requireNonNull(username);
		Objects.requireNonNull(password);

		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			logger.error(" ***Login attempt FAILED***  User : "+username+ " Requested Resource :"+request.getRequestURI()+
					" IP address : "+request.getRemoteAddr()+" Host: " + request.getRemoteHost());
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}	
	
	@RequestMapping(value = "/validation", method = RequestMethod.POST)
	public String validateJwtToken(@RequestBody JwtRequest tokenRequest)
			throws Exception {	
		
		String jwtToken = tokenRequest.getJwtToken();

		String tokenValidity = "invalid";
		
		if(jwtTokenUtil.getUsernameFromToken(jwtToken) != null && 
								jwtTokenUtil.validateToken(jwtToken)){			
			tokenValidity = "valid";
		}

		return tokenValidity;
	}
	
	@RequestMapping(value = "/acr/validation", method = RequestMethod.POST)
	public String validateACRToken(@RequestBody JwtRequest tokenRequest)
			throws Exception {	
		
		String jwtToken = tokenRequest.getJwtToken();
		String tokenValidity = "invalid";
		
		if(jwtTokenUtil.getUsernameFromToken(jwtToken) != null && 
				jwtTokenUtil.getUsernameFromToken(jwtToken).equalsIgnoreCase(ACR_USER) && 
				jwtTokenUtil.validateToken(jwtToken)){			
			tokenValidity = "valid";
		}	

		return tokenValidity;
	}
	
	@RequestMapping(value = "/ccp/validation", method = RequestMethod.POST)
	public String validateCCPToken(@RequestBody JwtRequest tokenRequest)
			throws Exception {	
		
		String jwtToken = tokenRequest.getJwtToken();
		String tokenValidity = "invalid";
		
		if(jwtTokenUtil.getUsernameFromToken(jwtToken) != null && 
				jwtTokenUtil.getUsernameFromToken(jwtToken).equalsIgnoreCase(CCP_USER) && 
				jwtTokenUtil.validateToken(jwtToken)){			
			tokenValidity = "valid";
		}				
	
		return tokenValidity;
	}
	
	@RequestMapping(value = "/cmo/validation", method = RequestMethod.POST)
	public String validateCMOToken(@RequestBody JwtRequest tokenRequest)
			throws Exception {	
		
		String jwtToken = tokenRequest.getJwtToken();
		String tokenValidity = "invalid";
		
		if(jwtTokenUtil.getUsernameFromToken(jwtToken) != null && 
				jwtTokenUtil.getUsernameFromToken(jwtToken).equalsIgnoreCase(CMO_USER) && 
				jwtTokenUtil.validateToken(jwtToken)){			
			tokenValidity = "valid";
		}				
	
		return tokenValidity;
	}
}
