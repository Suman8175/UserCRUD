package com.suman.blogging.bean.response;


import lombok.Data;

@Data
public class UserResponse {
    private Long userId;
    private String firstname;
    private String lastname;
    private String email;
    private String role;
    private String imagePath;
    private Long phoneNumber;
}
