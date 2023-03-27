package com.example.demosecurity.auth;

import com.example.demosecurity.Config.JwtService;
import com.example.demosecurity.user.Role;
import com.example.demosecurity.user.User;
import com.example.demosecurity.user.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepo repo;
    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {


        var user= User.builder()
                .firstname((request.getFirstname()))
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repo.save(user);
        var jwtToken= jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        // If the user is a valid user then only give the token.
       Authentication authentication= authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

       if(authentication.isAuthenticated()){
           var user=repo.findByEmail(request.getEmail())
                   .orElseThrow();
           var jwtToken= jwtService.generateToken(user);
           return AuthenticationResponse.builder()
                   .token(jwtToken)
                   .build();
       }else{
           throw new UsernameNotFoundException("invalid user request!");
       }

    }
}
