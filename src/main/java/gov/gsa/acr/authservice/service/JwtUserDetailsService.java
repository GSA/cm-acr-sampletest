package gov.gsa.acr.authservice.service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {		 
		if (user.equalsIgnoreCase(username)) {
			return new User(user, password, getAuthority(username));
		} else if (ccpUser.equalsIgnoreCase(username)) {
			return new User(ccpUser, ccpPassword, getAuthority(username));
		} else {
			throw new UsernameNotFoundException("User not found with username : " + username);
		}
	}

	private Set<SimpleGrantedAuthority> getAuthority(String username) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		if (user.equalsIgnoreCase(username)) {
			authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
			authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
			authorities.add(new SimpleGrantedAuthority("ROLE_INTERNAL_USER"));
		}
		else if (ccpUser.equalsIgnoreCase(username)) {
			authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
			authorities.add(new SimpleGrantedAuthority("ROLE_EXTERNAL_USER"));
		} else {
			throw new UsernameNotFoundException("User not found with username : " + username);
		}
		return authorities;
	}

}
