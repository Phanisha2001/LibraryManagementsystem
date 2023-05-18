package com.LibraryManagementSystem.securityconfig;

import com.LibraryManagementSystem.exception.NotFoundException;
import com.LibraryManagementSystem.service.UserService;

import io.jsonwebtoken.ExpiredJwtException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserService userService;

	@Autowired
	private JwtConfig jwtConfig;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		var auth = new DaoAuthenticationProvider();
		auth.setUserDetailsService(userService);
		auth.setPasswordEncoder(passwordEncoder());
		return auth;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/js/**", "/css/**", "/img/**").permitAll().anyRequest().authenticated()
				.and()
				.addFilterBefore(customValidationFilter(), UsernamePasswordAuthenticationFilter.class)
				.formLogin().successHandler((request, response, authentication) -> {
					Cookie cookie = new Cookie("Authorization",
							Base64.getEncoder().encodeToString(("Bearer " + jwtConfig.generateToken(authentication.getName())).getBytes()));
					cookie.setPath("/");
					cookie.setMaxAge(Integer.MAX_VALUE);
					response.addCookie(cookie);
					response.sendRedirect("/");
				}).loginPage("/login").permitAll().and().logout().invalidateHttpSession(true)
				.clearAuthentication(true).logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				.logoutSuccessUrl("/login?logout").permitAll();
	}

	private OncePerRequestFilter customValidationFilter() {
		return new OncePerRequestFilter() {
			@Override
			protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException, ServletException, IOException {
				if (!("/".equals(request.getRequestURI()) || "/login".equals(request.getRequestURI())
						|| "/logout".equals(request.getRequestURI()))) {

					Optional<Cookie> authCookie = Arrays.stream(request.getCookies()).filter(k -> "Authorization".equalsIgnoreCase(k.getName())).findFirst();
					if (!authCookie.isPresent()) {
						throw new NotFoundException("No JWT token found in the request");
					}
					String token = new String(Base64.getDecoder().decode(authCookie.get().getValue())).substring(7); // Remove "Bearer " prefix

					// Perform JWT token validation
					String username;
					try {
						username = jwtConfig.getUsernameFromToken(token);
					} catch (ExpiredJwtException ex) {
						throw new NotFoundException("JWT Token expired. Please login again: http://localhost:9080/login");
					}
					UserDetails userDetails = userService.loadUserByUsername(username);

					if (userDetails == null) {
						throw new NotFoundException("Invalid user details in JWT token");
					}
				}
				filterChain.doFilter(request, response);
			}
		};
	}
}