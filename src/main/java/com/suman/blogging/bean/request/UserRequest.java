package com.suman.blogging.bean.request;

import lombok.Data;

@Data
public class UserRequest {
    private String firstName;
    private String lastName;
    private String newPassword;
    private String oldPassword;
    private Long phoneNumber;
}
