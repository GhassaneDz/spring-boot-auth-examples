package net.secudev.auth.model.user;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ManyToMany;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.secudev.auth.model.common.AbstractEntity;
import net.secudev.auth.model.role.Role;

@Entity
@ToString(callSuper = true, includeFieldNames = true)
public class User extends AbstractEntity {

	@NotEmpty
	@Size(min = 1, max = 20)
	@Column(nullable = false, unique = true)
	@Getter
	@Setter
	private String login;

	@NotEmpty
	@Getter
	@Setter
	private String passwordHash;

	@ManyToMany(fetch = FetchType.LAZY)
	private Set<Role> roles = new HashSet<Role>();

	@Email
	@Column(unique = true)
	@Getter
	@Setter
	private String email;

	@Getter
	@Setter
	@Column(unique = true)
	private String apiToken;

	@Getter
	private LocalDateTime apiTokenExpirationDate;

	@Getter
	private String validationCode;
	
	@Getter
	private LocalDateTime validationCodeExpirationDate;

	@Getter
	@Setter
	private boolean enabled;

	@Getter
	@Setter
	private String lastIp;

	@Getter
	@Setter
	LocalDateTime lastAccessDate;

	protected User() {
	}

	public User(String login, String passwordHash, String email) {
		this.setLogin(login);
		this.setPasswordHash(passwordHash);
		this.setEmail(email);
	}

	public User(String login, String passwordHash, String email, List<Role> roles) {
		this(login, passwordHash, email);
		if (roles != null) {
			for (Role role : roles) {				
				this.addRole(role);
			}
		}
	}

	public void addRole(Role role) {
		if (role != null)
			this.roles.add(role);
	}

	public void removeRole(Role role) {
		if (role != null)
			this.roles.remove(role);
	}

	public List<Role> getRoles() {	
		return new ArrayList<Role>(roles);
	}

	public String generateValidationCode(int expirationDays) {
		this.validationCode = UUID.randomUUID().toString();
		this.validationCodeExpirationDate = LocalDateTime.now().plusDays(expirationDays);
		return this.validationCode;
	}

	public String createAccessToken(int expirationDays) {
		this.apiToken = UUID.randomUUID().toString();
		this.apiTokenExpirationDate = LocalDateTime.now().plusDays(expirationDays);
		return this.apiToken;
	}

	public void revokeAccess() {
		this.validationCode = "";
		this.validationCodeExpirationDate=LocalDateTime.now().minusMinutes(5);
		this.apiToken = "";
		this.apiTokenExpirationDate = LocalDateTime.now().minusMinutes(5);
	}
}
