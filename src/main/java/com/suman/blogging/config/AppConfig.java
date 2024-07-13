package com.suman.blogging.config;

import com.cloudinary.Cloudinary;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class AppConfig {
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public Cloudinary getCloudinary(){
        Map<Object, Object> config=new HashMap<>();
        config.put("cloud_name","dhmdgbhby");
        config.put("api_key","837818452676554");
        config.put("api_secret","FT_05xblmqSrIKKnNq8VVUiP7ww");
        config.put("secure",true);
        return new Cloudinary(config);
    }

}
