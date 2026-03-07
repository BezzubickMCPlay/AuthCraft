package com.authcraft.web;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Standard API response wrapper for all REST endpoints.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse {
    
    private boolean success;
    private String message;
    private Object data;
    private String error;
    private long timestamp;
    
    public ApiResponse() {
        this.timestamp = System.currentTimeMillis();
    }
    
    public ApiResponse(boolean success, String message) {
        this();
        this.success = success;
        this.message = message;
    }
    
    public ApiResponse(boolean success, String message, Object data) {
        this(success, message);
        this.data = data;
    }
    
    public static ApiResponse success(String message) {
        return new ApiResponse(true, message);
    }
    
    public static ApiResponse success(String message, Object data) {
        return new ApiResponse(true, message, data);
    }
    
    public static ApiResponse error(String error) {
        ApiResponse response = new ApiResponse(false, null);
        response.setError(error);
        return response;
    }
    
    public static ApiResponse error(String message, String error) {
        ApiResponse response = new ApiResponse(false, message);
        response.setError(error);
        return response;
    }
    
    // Getters and setters
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public Object getData() {
        return data;
    }
    
    public void setData(Object data) {
        this.data = data;
    }
    
    public String getError() {
        return error;
    }
    
    public void setError(String error) {
        this.error = error;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
}
