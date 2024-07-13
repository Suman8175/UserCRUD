package com.suman.blogging.exception;

import lombok.Data;

@Data
public class AppCustomMessage {
    private int status;
    private String message;
    private long timeStamp;

}
