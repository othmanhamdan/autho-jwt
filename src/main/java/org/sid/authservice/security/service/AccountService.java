package org.sid.authservice.security.service;

import org.sid.authservice.security.entities.AppRole;
import org.sid.authservice.security.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void AddUserToRole(String userName, String roleName);
    AppUser loadUserByUserName(String userName);
    List<AppUser> listUser();

}
