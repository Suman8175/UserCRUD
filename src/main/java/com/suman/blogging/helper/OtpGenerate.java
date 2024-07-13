package com.suman.blogging.helper;


import org.springframework.stereotype.Component;
import java.util.Random;

@Component
public class OtpGenerate {

    public String generateOTP(){


        Random random=new Random();
        int randomNumber= random.nextInt(999999);
        StringBuilder output= new StringBuilder(Integer.toString(randomNumber));
        while (output.length()<6){
            output.insert(0, "0");

        }
        return output.toString();
    }

}
