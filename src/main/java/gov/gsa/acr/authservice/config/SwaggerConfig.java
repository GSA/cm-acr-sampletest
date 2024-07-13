package gov.gsa.acr.authservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;

@Configuration
@ComponentScan(basePackages = "gov.*")
public class SwaggerConfig {

	@Bean
	public OpenAPI openAPI() throws Exception {
		return new OpenAPI()
				.info(new Info()
						.title("ACR Authentication Service")
						.description("This microservice allows authentication of authorization of ACR microservice.")
						.version("v1")
						.contact(new Contact().name("General Services Administration"))
						.license(new License().name("LICENSE")))
				.tags(Arrays.asList());


	}
}
