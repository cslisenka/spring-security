package com.example.demosecuritywebflux;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@SpringBootApplication
@EnableWebFluxSecurity
public class DemoSecurityWebfluxApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoSecurityWebfluxApplication.class, args);
	}

	@GetMapping("/service")
	public Mono<String> service() {
		return Mono.just("webflux service");
	}

	@GetMapping("/user/service")
	public Mono<String> userService() {
		return Mono.just("webflux user service");
	}

	@GetMapping("/admin/service")
	public Mono<String> adminService() {
		return Mono.just("webflux aadmin service");
	}

	// TODO configure LDAP (https://stackoverflow.com/questions/50506803/spring-security-webflux-and-ldap)
	// TODO we should use ReactiveAuthenticationManagerAdapter to adapt existing LDAP authentication manager to reactuve

	// TODO configure actuator security (using EndpointRequest)

	// Setting up webflux security
	@Bean
	public MapReactiveUserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("user")
				.roles("USER")
				.build();

		UserDetails admin = User.withDefaultPasswordEncoder()
				.username("admin")
				.password("admin")
				.roles("USER", "ADMIN")
				.build();
		return new MapReactiveUserDetailsService(user, admin);
	}

	// Special class used only for webflux applications
	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		//  .pathMatchers("/admin").hasAuthority("ROLE_ADMIN")
		http
			.authorizeExchange()
				.pathMatchers("/service").permitAll()
				.pathMatchers("/admin/*").hasRole("ADMIN")
				.anyExchange().authenticated()
			.and()
				.httpBasic()
			.and()
				.formLogin();
		return http.build();
	}
}