package net.secudev.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import net.secudev.auth.security.Blacklist;

@Component
public class StartupTasks implements ApplicationRunner {

	@Autowired
	private Blacklist blacklist;
	
	@Override
	public void run(ApplicationArguments args) throws Exception {
		blacklist.loadDisabledFromDB();		
	}

}
