package com.chinadci.rdc.ssoserver.models;

import lombok.Data;

import java.util.List;

@Data
public class UserInfo {

    private int id;
    private String userName;
    private String passwordhash;

    private List<RoleInfo> roles;
}
