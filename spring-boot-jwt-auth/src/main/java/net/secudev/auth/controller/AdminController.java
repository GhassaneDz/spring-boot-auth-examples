package net.secudev.auth.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import net.secudev.auth.model.role.IRoleRepository;
import net.secudev.auth.model.role.Role;
import net.secudev.auth.model.user.IUserRepository;
import net.secudev.auth.model.user.User;
import net.secudev.auth.security.Blacklist;

@RestController
@PreAuthorize("hasRole('ROLE_admin')")
@RequestMapping("/admin/")
public class AdminController {

	@Autowired
	private Blacklist blacklist;

	@Autowired
	private IUserRepository users;

	@Autowired
	private IRoleRepository roles;

	@GetMapping("me")
	public String me() {
		return SecurityContextHolder.getContext().getAuthentication().getName();
	}

	// ajouter a la blacklist et desactiver

	// activer et enlever de la blacklist

	// afficher la blacklist
	@GetMapping("blacklist")
	public List<String> blacklist() {
		return blacklist.getDisabled();
	}

	@GetMapping("/role")
	public List<String> usersInRole(@RequestBody String label) {

		Role role = roles.findByLabel(label);
		List<String> result = new ArrayList<>();

		if (role != null) {
			List<User> inRole = users.findByRolesContains(role);

			for (User u : inRole) {
				result.add(u.getLogin());
			}
		}

		return result;
	}

}
