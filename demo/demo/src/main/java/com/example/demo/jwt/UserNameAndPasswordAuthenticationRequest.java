package com.example.demo.jwt;

public class UserNameAndPasswordAuthenticationRequest {

  private String username;
  private String password;

  public UserNameAndPasswordAuthenticationRequest() {
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }
}
