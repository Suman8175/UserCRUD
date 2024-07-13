package com.suman.blogging.service;

import com.suman.blogging.bean.request.LoginCredentials;
import com.suman.blogging.bean.request.UserRequest;
import com.suman.blogging.bean.response.JwtResponse;
import com.suman.blogging.bean.response.UserResponse;
import com.suman.blogging.entity.User;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface UserService {

boolean createUser(User user);

JwtResponse loginUser(LoginCredentials loginCredentials);

String  logOutUser(String token);

UserResponse getUserById();

JwtResponse createRefreshToken(String refreshToken);

boolean createUserWithImageUpload(User user, MultipartFile file);

    boolean updateUser(UserRequest userRequest);

    boolean updateUserImage(MultipartFile userImage);
}
