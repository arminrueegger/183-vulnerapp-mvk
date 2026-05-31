package ch.bbw.m183.vulnerapp;

import java.io.IOException;

import ch.bbw.m183.vulnerapp.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public UserDetailsService userDetailsService(UserRepository userRepository) {
		return username -> userRepository.findById(username)
				.map(u -> User.withUsername(u.getUsername())
						.password(u.getPassword())
						.roles(u.getRole())
						.build())
				.orElseThrow(() -> new UsernameNotFoundException(username));
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		var csrfHandler = new CsrfTokenRequestAttributeHandler();

		return http
				.authorizeHttpRequests(auth -> auth
						.requestMatchers(HttpMethod.GET, "/", "/index.html", "/script.js", "/robots.txt", "/favicon.ico").permitAll()
						.requestMatchers(HttpMethod.GET, "/api/blog").permitAll()
						.requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()
						.requestMatchers("/login", "/logout").permitAll()
						.requestMatchers("/api/admin/**").hasRole("ADMIN")
						.anyRequest().authenticated())
				.formLogin(form -> form
						.successHandler((req, res, auth) -> res.setStatus(HttpStatus.OK.value()))
						.failureHandler((req, res, ex) -> res.setStatus(HttpStatus.UNAUTHORIZED.value())))
				.logout(logout -> logout
						.logoutSuccessHandler((req, res, auth) -> res.setStatus(HttpStatus.NO_CONTENT.value())))
				.csrf(csrf -> csrf
						.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
						.csrfTokenRequestHandler(csrfHandler))
				.addFilterAfter(new CsrfCookieFilter(), UsernamePasswordAuthenticationFilter.class)
				.exceptionHandling(eh -> eh
						.defaultAuthenticationEntryPointFor(
								new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
								req -> req.getRequestURI().startsWith("/api/")))
				.build();
	}

	static class CsrfCookieFilter extends OncePerRequestFilter {
		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
				throws ServletException, IOException {
			var token = (CsrfToken) request.getAttribute("_csrf");
			if (token != null) {
				token.getToken();
			}
			chain.doFilter(request, response);
		}
	}
}
