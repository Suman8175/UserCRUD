package com.suman.blogging.security;

import com.suman.blogging.entity.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class LoggedUser {
    public static synchronized User findUser(){
        Authentication authentication= SecurityContextHolder.getContext().getAuthentication();
        return (User) authentication.getPrincipal();
    }
}