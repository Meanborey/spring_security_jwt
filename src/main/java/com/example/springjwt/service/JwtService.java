package com.example.springjwt.service;

import com.example.springjwt.model.User;
import com.example.springjwt.repository.JwtRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JwtService implements UserDetailsService {

    private final JwtRepository jwtRepository;

    public JwtService(JwtRepository jwtRepository) {
        this.jwtRepository = jwtRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User users = jwtRepository.findUserByUsername(username);

        return (UserDetails) User.builder()
                .username(users.getUsername())
                .password(users.getPassword())
                .roles("USER")
                .build();
    }
}
