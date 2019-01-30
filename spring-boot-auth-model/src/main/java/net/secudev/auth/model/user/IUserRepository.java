package net.secudev.auth.model.user;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import net.secudev.auth.model.role.Role;

public interface IUserRepository extends JpaRepository<User, Long> {

	boolean existsByLogin(String login);

	User findByLogin(String login);

	User findByApiToken(String apiToken);

	User findByEmail(String email);

	User findByLastIp(String ip);

	User findByValidationCode(String code);

	List<User> findByRolesContains(Role role);

	List<User> findByEnabledTrueOrderByLoginAsc();

	List<User> findByEnabledFalseOrderByLoginAsc();

	List<User> findByLastAccessDateBetweenOrderByLoginAsc(LocalDateTime debut, LocalDateTime fin);

	List<User> findByApiTokenExpirationDateBetweenOrderByLoginAsc(LocalDateTime debut, LocalDateTime fin);

}
