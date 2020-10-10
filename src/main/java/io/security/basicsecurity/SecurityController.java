package io.security.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){
        return "Hello";
    }

    @GetMapping("loginPage")
    public String loginPage(){
        return "loginPage";
    }
    @GetMapping("/user")
    public String userPage(){
        return "user";
    }
    @GetMapping("/admin/pay")
    public String adminPayPage(){
        return "adminPay";
    }
    @GetMapping("/admin/**")
    public String adminPage(){
        return "admin";
    }

    @GetMapping("/denied")
    public String denied(){
        return "denied";
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }
}
