package com.tdev.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;

@SpringBootApplication
@OpenAPIDefinition(info = @Info(title = "Documentation de gestion de login", version = "2.0", description = "Information sur l'inscription et l'authentifcation"))
public class SpringbootSecurityLoginApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringbootSecurityLoginApplication.class, args);
	}

}
