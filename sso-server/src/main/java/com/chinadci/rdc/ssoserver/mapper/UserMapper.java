package com.chinadci.rdc.ssoserver.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.jdbc.SQL;

public class UserMapper {
    public String getUserByName(@Param("username") String userName)  {

        SQL sql = new SQL();
        sql.SELECT("id, username, passwordhash");
        sql.FROM("aspnetusers");
        sql.WHERE("username = #{username}");
        return sql.toString();
    }
}
