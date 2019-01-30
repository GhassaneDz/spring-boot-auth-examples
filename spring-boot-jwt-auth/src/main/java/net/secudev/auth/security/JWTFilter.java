package net.secudev.auth.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JWTFilter extends OncePerRequestFilter {

	@Autowired
	private JWTService jwtService;	
	

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// Extraire le JWT des headers et valider si il est conforme
		String header = request.getHeader("Authorization");

		// Si le header Authorization est vide ou s'il ne commence pas par Bearer on
		// passe au filtre suivant
		if (header == null || !header.startsWith("Bearer ")) {
			//logger.trace(request.getRemoteAddr() + " : Requete sans Header ou Bearer absent ");
			filterChain.doFilter(request, response);
			return;
		}

		// On supprime le prefixe afin de n'avoir que le texte du JWT
		String jwt = header.replace("Bearer ", "");
		logger.trace(jwt);
		
		
		// Créer le contexte de sécurité à partir du jwt via le jwtservice (homemade)
		try {
			
			UsernamePasswordAuthenticationToken auth = jwtService.getAuthenticationFromJWT(jwt);
			if(auth == null)			{
				throw new Exception("Auth est null....");
			}
			
			SecurityContextHolder.getContext().setAuthentication(auth);
			
		}		
		catch (Exception e) {
			
			String ex=e.toString();
			logger.trace(request.getRemoteAddr() +ex);			
			((HttpServletResponse) response).setStatus(HttpServletResponse.SC_FORBIDDEN);		
			((HttpServletResponse) response).getWriter().write(ex);				
			return;
		}
		
	
		// Si alerte rouge, compromission etc, changer le secret dans la conf puis
		// redemarrer
		// Sur le front il est conseillé de protéger le JWT dans un cookie securisé pour
		// prévenir le XSS
		// Ne jamais stocker d'infos sensibles dans un JWT (mot de passe par ex)

		/**
		 * Evolutions Eventuelles
		 * 
		 * -Faire cohabiter les filtres JWT et APIKEY en les mettant à la suite -Tenir a
		 * jour une liste de token blacklistés en mémoire dans une hashmap ou ds une db
		 * KeyValue inmemory genre REDIS (si plusieurs services ou besoin de persister
		 * après reboot) -Logger les accès dans la bdd, blocker les abus etc
		 **/

		filterChain.doFilter(request, response);
	}
}

