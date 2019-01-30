package net.secudev.auth.security;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import net.secudev.auth.model.user.IUserRepository;
import net.secudev.auth.model.user.User;

@Component
public class Blacklist {
	
	@Autowired
	private IUserRepository utilisateurs;
	
	private Set<String> disabled = new HashSet<String>();
	
	private Logger logger = LoggerFactory.getLogger(this.getClass());
	
	//a chaque demarrage de l'appli on appellera cette methode lit la liste des users disabled et les ajoute a la blacklist
	public void loadDisabledFromDB()
	{
		for(User u : utilisateurs.findByEnabledFalseOrderByLoginAsc())
		{
			disabled.add(u.getLogin());
			
			logger.info("Blacklisted "+u.getLogin());
			
		}
	}
	
	public boolean userInList(String user)
	{
		return disabled.contains(user);
	}
	
	public void addUser(String user)
	{
		disabled.add(user);
		logger.info("Blacklisted "+user);
	}
	
	public void removeUser(String user)
	{
		disabled.remove(user);
		logger.info("UNBlacklisted "+user);
	}

	public List<String> getDisabled() {
		return new ArrayList<String>(disabled);
	}	

}
