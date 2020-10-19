package spring.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import spring.web.model.User;
import spring.web.service.UserService;

import java.util.HashSet;

@Controller
public class LoginController {

    @Autowired
    private UserService userService;

    @GetMapping(value = "/login")
    public String login() {
        return "login";
    }

    @PostMapping(value = "/reg")
    public String registration(@ModelAttribute("user") User user) {
        user.setRoles(new HashSet<>());
        user.getRoles().add(userService.findRoleByName("USER"));
        if (user.getName().equals("admin")) {
            user.getRoles().add(userService.findRoleByName("ADMIN"));
        }
        userService.addUser(user);
        return "redirect:/login";
    }
}