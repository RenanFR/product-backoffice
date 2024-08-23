package com.agamercado.backoffice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.agamercado.backoffice.jwt.JwtAuthenticationFilter;
import com.agamercado.backoffice.jwt.JwtAuthorizationFilter;
import com.agamercado.backoffice.jwt.JwtUtil;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig implements WebMvcConfigurer {

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private AuthenticationManagerBuilder authenticationManagerBuilder;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		AuthenticationManager authenticationManager = authenticationManagerBuilder.getOrBuild();

		http.csrf().disable()
				.authorizeHttpRequests(
						(requests) -> requests.requestMatchers("/login").permitAll().anyRequest().authenticated())
				.addFilter(new JwtAuthenticationFilter(authenticationManager, jwtUtil))
				.addFilterBefore(new JwtAuthorizationFilter(jwtUtil), JwtAuthenticationFilter.class).formLogin()
				.disable();

		return http.build();
	}

	@Autowired
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.ldapAuthentication().userDnPatterns("uid={0},ou=people").groupSearchBase("ou=groups").contextSource()
				.url("ldap://localhost:8389/dc=springframework,dc=org").and().passwordCompare()
				.passwordEncoder(new BCryptPasswordEncoder()).passwordAttribute("userPassword");
	}

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**").allowedOrigins("http://localhost:3000")
				.allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS").allowedHeaders("*").allowCredentials(true);
	}

}
