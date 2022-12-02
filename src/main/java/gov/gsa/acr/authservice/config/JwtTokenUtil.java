package gov.gsa.acr.authservice.config;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -2550185165626007488L;
	
	public static final long JWT_TOKEN_VALIDITY = 5*60*60;

	@Value("${ACR_AUTH_JWT_SECRET}")
	private String secret;

	@Value("${jwt.authorities.key}")
	public String AUTHORITIES_KEY;

	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	public Date getIssuedAtDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getIssuedAt);
	}

	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	public Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	public String[] getRoles(String token) {
		return getClaimFromToken(token, claims -> getAuthorities(claims).split(","));
	}


	private String getAuthorities(Claims claims){
		if (claims == null) throw new IncorrectClaimException(null, null, "Invalid or null claim ");
		String authorities = claims.get(AUTHORITIES_KEY, String.class);
		if (authorities == null) throw new MissingClaimException(null, claims, "No roles/authorities found in this Token");
		return authorities;
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	private Boolean ignoreTokenExpiration(String token) {
		// here you specify tokens, for that the expiration is ignored
		return false;
	}

	public String generateToken(Authentication authentication) {
		Map<String, Object> claims = new HashMap<>();
		claims.put(AUTHORITIES_KEY, authentication.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(",")));
		return doGenerateToken(claims, authentication.getName());
	}

	private String doGenerateToken(Map<String, Object> claims, String subject) {
		// set the token validity to 24 hours.
		Calendar cal = Calendar.getInstance();
	    cal.add(Calendar.HOUR_OF_DAY, 24);
	    Date expiryDate = cal.getTime();
	     
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(expiryDate).signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	public Boolean canTokenBeRefreshed(String token) {
		return (!isTokenExpired(token) || ignoreTokenExpiration(token));
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	
	public Boolean validateToken(String jwtToken) {
		return (parseToken(jwtToken) && !isTokenExpired(jwtToken));
	}
	
	private Boolean parseToken(String jwtToken) {		
		try {
			Jws<Claims> jwt = Jwts.parser().setSigningKey(secret).parseClaimsJws(jwtToken);		
			
			if(jwt != null)
				return true;
			
		} catch (ExpiredJwtException e) {		
			return false;
		} catch (UnsupportedJwtException e) {			
			return false;
		} catch (MalformedJwtException e) {				
			return false;
		} catch (SignatureException e) {		
			return false;
		} catch (IllegalArgumentException e) {		
			return false;
		}
		
		return false;
	}
}
