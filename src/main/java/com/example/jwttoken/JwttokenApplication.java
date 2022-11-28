package com.example.jwttoken;

import com.example.jwttoken.model.Role;
import com.example.jwttoken.model.User;
import com.example.jwttoken.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwttokenApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwttokenApplication.class, args);
	}

	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));

			userService.saveUser(new User(null, "John Smith", "john123", "123", new ArrayList<>()));
			userService.saveUser(new User(null, "Kate Marsh", "kate123", "123", new ArrayList<>()));
			userService.saveUser(new User(null, "Dave Walker", "dave123", "123", new ArrayList<>()));

			userService.addRoleToUser("john123", "ROLE_USER");
			userService.addRoleToUser("kate123", "ROLE_MANAGER");
			userService.addRoleToUser("dave123", "ROLE_MANAGER");
			userService.addRoleToUser("dave123", "ROLE_ADMIN");
		};
	}
}
