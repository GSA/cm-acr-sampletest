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
	
	@Value("${ACR_READONLY_USER}")
	private String readonlyUser;
	
	@Value("${ACR_READONLY_PASSWORD}")
	private String readonlyPassword;	
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {		
		
		if (user.equalsIgnoreCase(username)) {
			return new User(user, password, new ArrayList<>());
		} else if (readonlyUser.equalsIgnoreCase(username)) {
			return new User(readonlyUser, readonlyPassword, new ArrayList<>()); 
		} else {
			throw new UsernameNotFoundException("User not found with username : " + username);
		}
	}

}
