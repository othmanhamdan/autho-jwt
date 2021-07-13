package org.sid.authservice;

import org.sid.authservice.security.entities.AppRole;
import org.sid.authservice.security.entities.AppUser;
import org.sid.authservice.security.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
//@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner start(AccountService accountService){
        return args -> {
            accountService.addNewRole(new AppRole(null,"USER"));
            accountService.addNewRole(new AppRole(null,"ADMIN"));
            accountService.addNewRole(new AppRole(null,"CUSTOMER_MANAGER"));
            accountService.addNewRole(new AppRole(null,"PRODUCT_MANAGER"));
            accountService.addNewRole(new AppRole(null,"BILLS_MANAGER"));

            accountService.addNewUser(new AppUser(null,"user1","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user2","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user3","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user4","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user5","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user6","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user7","1234",new ArrayList<>()));

            accountService.AddUserToRole("user1","USER");
            //accountService.AddUserToRole("user2","USER");
            accountService.AddUserToRole("user2","ADMIN");
            accountService.AddUserToRole("user3","CUSTOMER_MANAGER");
            accountService.AddUserToRole("user4","PRODUCT_MANAGER");
            accountService.AddUserToRole("user5","USER");
            accountService.AddUserToRole("user5","PRODUCT_MANAGER");
            accountService.AddUserToRole("user6","ADMIN");
            accountService.AddUserToRole("user6","BILLS_MANAGER");
        };
    }

}
