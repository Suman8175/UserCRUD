package com.suman.blogging.mapper;

import com.suman.blogging.bean.response.UserResponse;
import com.suman.blogging.entity.User;
import com.suman.blogging.helper.OtpGenerate;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class UserMapper {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final OtpGenerate otpGenerate;
    public  User mapUserRegisterData(User user){
        User mapUser=new User();
        mapUser.setUserId(0L);
        mapUser.setFirstname(user.getFirstname());
        mapUser.setLastname(user.getLastname());
        mapUser.setEmail(user.getEmail());
        mapUser.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        mapUser.setImagePath(user.getImagePath());
        mapUser.setRole(user.getRole());
        mapUser.setAccountBlocked(false);
        mapUser.setOtp(otpGenerate.generateOTP());
        mapUser.setAccountVerified(false);
        mapUser.setOtpTime(LocalDateTime.now());
        mapUser.setPhoneNumber(user.getPhoneNumber());
        return mapUser;
    }

    public UserResponse mapUserFetch(User user){
        UserResponse userResponse=new UserResponse();
        userResponse.setUserId(user.getUserId());
        userResponse.setFirstname(user.getFirstname());
        userResponse.setLastname(user.getLastname());
        userResponse.setEmail(user.getEmail());
        userResponse.setPhoneNumber(user.getPhoneNumber());
        userResponse.setRole(user.getRole());
        userResponse.setImagePath(user.getImagePath());
    return userResponse;
    }

}
