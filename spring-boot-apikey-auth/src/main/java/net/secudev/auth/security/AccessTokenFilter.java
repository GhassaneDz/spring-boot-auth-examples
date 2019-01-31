package net.secudev.auth.security;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import net.secudev.auth.model.role.Role;
import net.secudev.auth.model.user.IUserRepository;
import net.secudev.auth.model.user.User;

//Si on l'ajoute comme component il sera automatiquement utilisé
@Component
public class AccessTokenFilter extends OncePerRequestFilter {

	@Autowired
	IUserRepository users;

	private Logger logger = LoggerFactory.getLogger(this.getClass());

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		

		// 1 extraire le token des headers et valider si il est conforme
		String header = request.getHeader("Authorization");

		if (header == null || !header.startsWith("Bearer ")) {
			logger.trace("Requete sans header Authorisation ou qui ne débute pas par Bearer");
			filterChain.doFilter(request, response);
			return;
		}

		String token = header.replace("Bearer ", "");

		// 2 retrouver le user associé au token
		User user = users.findByApiToken(token);

		if (user != null) {

			// 3 Verifier si le user n'est pas bloqué puis si le token n'a pas expiré
			if (!user.isEnabled()) {

				String msg = "Utilisateur désactivé : " + user.getLogin();
				logger.trace(msg);
				((HttpServletResponse) response).setStatus(HttpServletResponse.SC_FORBIDDEN);
				((HttpServletResponse) response).getWriter().write(msg);
				return;
			}

			if (user.getApiTokenExpirationDate().isBefore(LocalDateTime.now())) {

				String msg = "Token expiré le " + user.getApiTokenExpirationDate() + " pour : " + user.getLogin();
				logger.trace(msg);
				((HttpServletResponse) response).setStatus(HttpServletResponse.SC_FORBIDDEN);
				((HttpServletResponse) response).getWriter().write(msg);
				return;
			}

			// 4 retrouver les roles de ce user
			List<SimpleGrantedAuthority> roles = new ArrayList<SimpleGrantedAuthority>();

			for (Role role : user.getRoles()) {
				SimpleGrantedAuthority sga = new SimpleGrantedAuthority("ROLE_" + role.getLabel());
				roles.add(sga);
			}

			// 5 creer le contexte de securité pour ce user

			UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user.getLogin(), null,
					roles);
			SecurityContextHolder.getContext().setAuthentication(auth);

			// 6 logger son acces et son IP
			user.setLastAccessDate(LocalDateTime.now());
			user.setLastIp(request.getRemoteAddr());

			users.save(user);

			// passer la main à la chaine de filtres suivants

		}

		filterChain.doFilter(request, response);

	}

}
