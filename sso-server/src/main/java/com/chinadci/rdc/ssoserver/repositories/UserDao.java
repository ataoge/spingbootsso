package com.chinadci.rdc.ssoserver.repositories;

import com.chinadci.rdc.ssoserver.mapper.UserMapper;
import com.chinadci.rdc.ssoserver.models.UserInfo;
import org.apache.ibatis.annotations.*;

import org.apache.ibatis.mapping.FetchType;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface UserDao {


    List<UserInfo> selectAllUsers();

    @SelectProvider(type = UserMapper.class, method = "getUserByName")
    @Results({

            @Result(id = true, property = "id", column = "id"),
            @Result(property = "roles", column = "id", many=@Many(select = "com.chinadci.rdc.ssoserver.repositories.RoleDao.fileRoleByUserId", fetchType = FetchType.LAZY))
    })
    UserInfo getUserByName(String userName);

}
