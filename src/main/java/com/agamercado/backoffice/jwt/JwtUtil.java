package com.agamercado.backoffice.jwt;

import java.util.ArrayList;
import java.util.Date;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

	private final String SECRET_KEY = "secret";

	public String generateToken(String username) {
		return Jwts.builder().setSubject(username).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
				.signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
	}

	public boolean validateToken(String token) {
		return getExpirationDate(token).after(new Date());
	}

	public Date getExpirationDate(String token) {
		return getClaims(token).getExpiration();
	}

	public Authentication getAuthentication(String token) {
		String username = getClaims(token).getSubject();
		return new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
	}

	private Claims getClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
	}
}
