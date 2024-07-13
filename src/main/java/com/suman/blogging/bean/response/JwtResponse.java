package com.suman.blogging.bean.response;
import lombok.*;


@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    int status;
    String token;
    String refreshToken;
    String email;
    String role;
}
