package net.secudev.auth.model.role;

import org.springframework.data.jpa.repository.JpaRepository;

public interface IRoleRepository extends JpaRepository<Role, Long> {
	
	Role findByLabel(String label);
	

}
