package net.secudev.auth;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class ScheduledTasks {
	
	@Scheduled(fixedDelay=5000)
	public void test()
	{
		System.out.println("j'apparais toutes les 5 secondes !!");
		//par exemple pour vérifier si un service externe répond, nettoyer des données prériodiquement etc
	}

}
