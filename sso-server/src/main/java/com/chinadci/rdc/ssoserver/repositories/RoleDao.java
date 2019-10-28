package com.chinadci.rdc.ssoserver.repositories;

import com.chinadci.rdc.ssoserver.models.RoleInfo;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface RoleDao {
    @Select("select id, name, displayname from aspnetroles where id in (select roleid from aspnetuserroles where userid = #{userid}) ")
    List<RoleInfo> fileRoleByUserId(int userid);
}
