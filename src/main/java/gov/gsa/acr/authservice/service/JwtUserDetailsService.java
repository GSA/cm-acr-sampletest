package gov.gsa.acr.authservice.service;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailsService implements UserDetailsService {

	@Value("${ACR_AUTH_USER}")
	private String user;
	
	@Value("${ACR_AUTH_PASSWORD}")
	private String password;
	
	@Value("${CCP_AUTH_USER}")
	private String ccpUser;
	
	@Value("${CCP_AUTH_PASSWORD}")
	private String ccpPassword;
	
	@Value("${CMO_AUTH_USER}")
	private String cmoUser;
	
	@Value("${CMO_AUTH_PASSWORD}")
	private String cmoPassword;

	@Value("${ADV_AUTH_USER}")
	private String advUser;

	@Value("${ADV_AUTH_PASSWORD}")
	private String advPassword;

	@Value("${ELIB_AUTH_USER}")
	private String elibUser;

	@Value("${ELIB_AUTH_PASSWORD}")
	private String elibPassword;

	@Value("${EBUY_AUTH_USER}")
	private String ebuyUser;

	@Value("${EBUY_AUTH_PASSWORD}")
	private String ebuyPassword;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {		 
		if (user.equalsIgnoreCase(username)) {
			return new User(user, password, new ArrayList<>());
		} else if (ccpUser.equalsIgnoreCase(username)) {
			return new User(ccpUser, ccpPassword, new ArrayList<>()); 
		} else if (cmoUser.equalsIgnoreCase(username)) {
			return new User(cmoUser, cmoPassword, new ArrayList<>()); 
		} else if (advUser.equalsIgnoreCase(username)) {
			return new User(advUser, advPassword, new ArrayList<>());
		} else if (elibUser.equalsIgnoreCase(username)) {
			return new User(elibUser, elibPassword, new ArrayList<>());
		} else if (ebuyUser.equalsIgnoreCase(username)) {
			return new User(ebuyUser, ebuyPassword, new ArrayList<>());
		} else {
			throw new UsernameNotFoundException("User not found with username : " + username);
		}
	}

}
