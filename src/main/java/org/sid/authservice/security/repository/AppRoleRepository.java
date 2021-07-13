package org.sid.authservice.security.repository;

import org.sid.authservice.security.entities.AppRole;
import org.sid.authservice.security.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByRoleName(String nameRole);
}
