package net.secudev.auth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {	

	@Autowired
	JWTFilter jwtFilter;	

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Considération pour le Front END
		// CSRF protege les requete autres que GET par le passage d'un token dedié
		// JWT lorsqu'utilisé et stocké coté front ailleurs que dans un cookie n'a pas
		// besoin de protection CSRF. ce n'est pas le browser qui authentifie mais ajax
		// avce le jwt
		// Nénamoins le JWT est plus exposé au attaques XSS, car si un autre site accède
		// au localstorage via un js malicieux il pique jwt
		
		//EN GROS il faut utiliser le localstorage du suer pour stocker le jwt ET prtoger son front des failles XSS
		//Certains frameworks front le proposent par exemple en nettoyant les balises script des les données saisies dans des formulaires

		/*
		 * Generally, CSRF happens when a browser automatically adds headers (i.e:
		 * Session ID within a Cookie), and then made the session authenticated. Bearer
		 * tokens, or other HTTP header based tokens that need to be added manually,
		 * would prevent you from CSRF.
		 * 
		 * Of course, but sort of off-topic, if you have a XSS vulnerability, an
		 * attacker could still access these tokens, but then it doesn't become a CSRF
		 * bug.
		 */

		//On desactive CSRF ansi que le formulaire de login auto généré et on active la protection CORS
		http.csrf().disable().cors().and().formLogin().disable()

				// Permet d'accèder a ces racines d'URL de facon anonyme (le controller de
				// login, un de tests et la doc d'api
				.authorizeRequests()
				.antMatchers("/ano/**").permitAll()
				.antMatchers("/test/**").permitAll()
				.antMatchers("/", "/csrf", "/v2/api-docs", "/swagger-resources/configuration/ui", "/swagger-resources",
						"/swagger-resources/configuration/security", "/swagger-ui.html", "/webjars/**")	.permitAll()

				// Maintenant toutes les autres sont soumises à authentification
				.anyRequest().authenticated().and()

				// Permet de capturer le header Authorization
				.httpBasic().and()

				// filtre qui va disséquer la requete http pour authentifier les requetes
				.addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class)
							

				// desactive les sessions car la communication est sans etat a conserver coté
				// serveur
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}
}
