package org.inlighting.controller;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.*;
import org.apache.shiro.subject.Subject;
import org.inlighting.bean.ResponseBean;
import org.inlighting.database.UserService;
import org.inlighting.database.UserBean;
import org.inlighting.exception.UnauthorizedException;
import org.inlighting.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class WebController {

    private static final Logger LOGGER = LogManager.getLogger(WebController.class);

    private UserService userService;

    @Autowired
    public void setService(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseBean login(@RequestParam("username") String username,
                              @RequestParam("password") String password) {
        UserBean userBean = userService.getUser(username);
        if (userBean.getPassword().equals(password)) {
            return new ResponseBean(200, "Login success", JWTUtil.sign(username, password));
        } else {
            throw new UnauthorizedException();
        }
    }

    @GetMapping("/article")
    public ResponseBean article() {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            return new ResponseBean(200, "You are already logged in", "登录成功你可以在这里返回登录用户才能看到的数据");
        } else {
            return new ResponseBean(200, "You are guest", "请求中没有token，但表没有登录过只能查看游客身份的数据");
        }
    }

    @GetMapping("/require_auth")
    @RequiresAuthentication
    public ResponseBean requireAuth() {
    	/*
    	 * @RequiresAuthentication 这个注解是是否进行身份验证 加上这个注解之后只有登录成功并且下次请求时候带着这个返回的token才能访问这个接口
    	 * 否则不能访问会报shiro中自定义的错误401 
    	 */
        return new ResponseBean(200, "You are authenticated", "登录成功才会有数据");
    }

    @GetMapping("/require_role")
    @RequiresRoles("admin")
    public ResponseBean requireRole() {
    	/*
    	 * @RequiresRoles("admin") 这个注解是权限验证，只有role=admin 的用户才可以访问这个接口
    	 */
        return new ResponseBean(200, "You are visiting require_role", "只有角色admin用户才能看到数据");
    }

    @GetMapping("/require_permission")
    @RequiresPermissions(logical = Logical.AND, value = {"view", "edit"})
    public ResponseBean requirePermission() {
    	/*
    	 * /@RequiresPermissions(logical = Logical.AND, value = {"view", "edit"})
    	 * 这个是对权限的功能进行验证的注解
    	 */
        return new ResponseBean(200, "You are visiting permission require edit,view", "只有view 和 edit 的角色才能看到数据");
    }

    @RequestMapping(path = "/401")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseBean unauthorized() {
        return new ResponseBean(401, "Unauthorized", null);
    }
}
