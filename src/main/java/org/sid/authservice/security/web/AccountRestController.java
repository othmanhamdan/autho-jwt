package org.sid.authservice.security.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.sid.authservice.security.entities.AppRole;
import org.sid.authservice.security.entities.AppUser;
import org.sid.authservice.security.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {
    @Autowired
    private AccountService accountService;
    @GetMapping(path = "/users")
    //@PostAuthorize("hasAuthority('USER')")
    public List<AppUser> getAllUser(){
        return  accountService.listUser();
    }
    @PostMapping(path = "/users")
    //@PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }
    @PostMapping(path = "/roles")
    //@PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }
    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser(@RequestBody AddUserToRoleForm addUserToRoleForm){
        accountService.AddUserToRole(addUserToRoleForm.getUserName(),addUserToRoleForm.getRoleName());
    }
    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
        String authtoken=request.getHeader("Authorization");
        if (authtoken!=null && authtoken.startsWith("Bearer ")){
            try {
                String jwt=authtoken.substring(7);
                Algorithm algorithm=Algorithm.HMAC256("MySecret1234");
                JWTVerifier jwtVerifier= JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String userName=decodedJWT.getSubject();
                AppUser appUser=accountService.loadUserByUserName(userName);
                String jwtAccessToken= JWT.create()
                        .withSubject(appUser.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis()+15*60*1000))
                        .withIssuer(request.getRequestURI().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idTokenMap=new HashMap<>();
                idTokenMap.put("access-token",jwtAccessToken);
                idTokenMap.put("refresh-token",jwt);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idTokenMap);
                }catch (Exception e){
                throw e;

                }
              }else {
                throw new RuntimeException("Refresh to token required");
             }

            }
}
@Data
class AddUserToRoleForm{
    private String userName;
    private String roleName;
}
