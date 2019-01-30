package net.secudev.auth;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import net.secudev.auth.model.role.IRoleRepository;
import net.secudev.auth.model.role.Role;
import net.secudev.auth.model.user.IUserRepository;
import net.secudev.auth.model.user.User;

@Component
public class InitData implements CommandLineRunner{

	@Autowired
	private IRoleRepository roles;
	@Autowired
	private IUserRepository users;
	
	@Autowired
	PasswordEncoder encoder;
	
	private Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Override
	public void run(String... args) throws Exception {
		
		//Si les users et les roles sont vides
		if(roles.count() == 0 && users.count()==0){
			
			logger.trace("Data vides, création ...");
						
			Role admin = new Role("admin");
			Role regular = new Role("regular");
			Role vip = new Role("vip");
			
			logger.trace("Ajout des rôles regular, admin et vip ...");
			roles.saveAll(Arrays.asList(regular, vip, admin));			
			
			User root = new User("admin", encoder.encode("password"), "admin@secudev.net",Arrays.asList(admin));
			root.generateValidationCode(2);
			root.createAccessToken(1);
			root.setEnabled(true);					
			users.save(root);				
			
			User bob = new User("bob", encoder.encode("password"), "bob@secudev.net",Arrays.asList(regular));
			bob.generateValidationCode(2);
			bob.createAccessToken(1);
			bob.setEnabled(true);
			users.save(bob);
			
			
			User alice = new User("alice", encoder.encode("password"), "alice@secudev.net",Arrays.asList(regular, vip));
			alice.generateValidationCode(2);			
			alice.createAccessToken(1);
			alice.setEnabled(true);
			users.save(alice);
			
			logger.trace("Ajout des utilisateurs admin, bob et alice ...");
			users.saveAll(Arrays.asList(root, bob, alice));
		}		
	}
}
