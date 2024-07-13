package com.suman.blogging.controller;

import com.suman.blogging.bean.request.LoginCredentials;
import com.suman.blogging.bean.request.UserRequest;
import com.suman.blogging.bean.response.JwtResponse;
import com.suman.blogging.bean.response.UserResponse;
import com.suman.blogging.entity.User;
import com.suman.blogging.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/v1/app")
@RequiredArgsConstructor
public class AuthenticationController {

    private final UserService userService;


    @PostMapping("/users")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> createUser(@RequestBody User user){
        boolean value = userService.createUser(user);
        return value ? new ResponseEntity<>(HttpStatus.CREATED) :new ResponseEntity<>(HttpStatus.NOT_ACCEPTABLE);
    }

    @PostMapping("/signup")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> createUserWithFormData( @RequestPart("userDetails") User user,
                                                     @RequestPart("userImage") MultipartFile file) throws IOException {
       boolean condition= userService.createUserWithImageUpload(user, file);
        return condition ? new ResponseEntity<>(HttpStatus.CREATED):
                            new ResponseEntity<>(HttpStatus.NOT_ACCEPTABLE);
    }

    @GetMapping("/login")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> login(@RequestBody LoginCredentials loginCredentials){
        JwtResponse jwtResponse = userService.loginUser(loginCredentials);
        return new ResponseEntity<>(jwtResponse,HttpStatus.OK);
    }

    @PostMapping("/logout")
    @PreAuthorize("hasAnyRole('User')")
    public ResponseEntity<?> logoutUser(@RequestHeader("Authorization") String token) {
        String value = userService.logOutUser(token);
        return new ResponseEntity<>(value,HttpStatus.OK);
    }

    @GetMapping
    @PreAuthorize("hasRole('User')")
    public List<String> getFruit(){
        List<String> fruit=new ArrayList<>();
        fruit.add("mango");
        fruit.add("apple");
        return fruit;
    }

    @PostMapping("/refreshToken")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> refreshToken(@RequestParam String refreshToken){
        JwtResponse refreshJwtToken = userService.createRefreshToken(refreshToken);
        return new ResponseEntity<>(refreshJwtToken,HttpStatus.CREATED);
    }




    @GetMapping("/users/me")
    @PreAuthorize("hasRole('User')")
    public ResponseEntity<?> getUserById(){
        UserResponse userById = userService.getUserById();
        return new ResponseEntity<>(userById,HttpStatus.OK);
    }

    @PatchMapping("/users")
    @PreAuthorize("hasRole('User')")
    public ResponseEntity<UserResponse> patchUser(
                                                  @RequestBody UserRequest userRequest) {
        boolean check = userService.updateUser(userRequest);
        return check ? new ResponseEntity<>(HttpStatus.CREATED):
                new ResponseEntity<>(HttpStatus.NOT_ACCEPTABLE);

    }
    @PostMapping("/users/images")
    @PreAuthorize("hasRole('User')")
    public ResponseEntity<?> updateUserPhoto( @RequestParam(required = true) MultipartFile userImage){
        boolean success = userService.updateUserImage( userImage);

        if (success) {
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }
    }


