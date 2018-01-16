package org.shop.controller;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashSet;
import java.util.Set;

public class MyRealm extends AuthorizingRealm {

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        Object principal = authenticationToken.getPrincipal();
        String password = "123";
        SimpleHash newPassword = new SimpleHash("md5", password, principal, 1024);
        ByteSource salt = ByteSource.Util.bytes(principal);
        return new SimpleAuthenticationInfo(principal,newPassword,salt,"myRealm");
    }

    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //通过username拿到数据库中的用户角色（用户名必须唯一）
        Object username = principalCollection.getPrimaryPrincipal();
        //用户角色用一个set<String>集合保存
        Set<String> set = new HashSet<String>();
        if (username.equals("a")){
            set.add("a");
        }
        if (username.equals("b")){
            set.add("b");
        }
        return new SimpleAuthorizationInfo(set);
    }
}
