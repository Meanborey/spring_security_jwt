package com.example.springjwt.repository;

import com.example.springjwt.model.User;
import jakarta.websocket.Extension;
import org.springframework.stereotype.Repository;

@Repository
public interface JwtRepository {

    User findUserByUsername(String username);


}
