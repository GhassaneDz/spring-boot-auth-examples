package net.secudev.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication(exclude= {UserDetailsServiceAutoConfiguration.class})
@EnableSwagger2
@EnableAsync
@EnableScheduling
public class SpringBootJwtAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootJwtAuthApplication.class, args);
	}
	
	@Bean
	public Docket swaggerEmployeeApi() {
	    return new Docket(DocumentationType.SWAGGER_2)
	        .select()
	            .apis(RequestHandlerSelectors.basePackage("net.secudev.auth.controller"))
	            .paths(PathSelectors.any())
	        .build()
	        .apiInfo(new ApiInfoBuilder().version("1.0").title("API basic AUTH").description("Documentation API v1.0").build());
	}


}

