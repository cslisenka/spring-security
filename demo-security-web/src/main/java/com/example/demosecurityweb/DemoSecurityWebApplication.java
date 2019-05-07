package com.example.demosecurityweb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
// Disables standard security configuration
@EnableWebSecurity
public class DemoSecurityWebApplication {

	public static final Logger log = LoggerFactory.getLogger(DemoSecurityWebApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(DemoSecurityWebApplication.class, args);
	}

	@GetMapping("/service")
	public String service() {
		return "service";
	}

	@GetMapping("/user/service")
	public String userService() {
		return "user service";
	}

	@GetMapping("/admin/service")
	public String appService() {
		return "admin Service";
	}

	// TODO use method security (for managed operations)
	// This adapter is only used for spring-web tomcat based deployment
	@Configuration
	public class BasicConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		public void configure(WebSecurity web) throws Exception {
			super.configure(web);
			log.info("init web security {}", web);
		}

		// Only works with DAOAuthenticationProvider
		// If other type of authentication manager is used - ignored
//		@Bean
//		@Override
//		public UserDetailsService userDetailsService() {
//			log.info("configuring user details service");
//			UserDetails user =
//					User.withDefaultPasswordEncoder()
//							.username("user")
//							.password("password")
//							.roles("USER")
//							.build();
//
//			return new InMemoryUserDetailsManager(user);
//		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// TODO use apache DS server
			// TODO use LDAP authentication
			// https://memorynotfound.com/spring-security-spring-ldap-authentication-example/

//			auth
//					.ldapAuthentication()
//					.userDnPatterns("uid={0},ou=people")
//					.groupSearchBase("ou=groups");

			// Using noop password encoder (store password as plain text)
			// https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#pe-dpe
			auth
				.inMemoryAuthentication()
					.withUser("user").password("{noop}password").roles("USER")
					.and()
					.withUser("admin").password("{noop}admin").roles("USER", "ADMIN");

			log.info("init auth manager {}", auth);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// TODO different auth type - basic, form, etc. ?

			http
				.authorizeRequests()
					.antMatchers("/service").permitAll()
					.antMatchers("/actuator/*").hasRole("ADMIN")
					.antMatchers("/admin/*").hasRole("ADMIN")
					.anyRequest().authenticated() // Other requests
				.and()
					.httpBasic();

			log.info("init http security {}", http);
		}
	}
}