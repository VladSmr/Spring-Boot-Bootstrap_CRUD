package spring.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import spring.web.model.Role;
import spring.web.model.User;
import spring.web.service.UserService;

import java.util.HashSet;
import java.util.Set;

@Controller
public class AdminController {

    @Autowired
    private UserService userService;

    @GetMapping(value = "/admin")
    public String admin(ModelMap model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("user", user);
        return "/admin";
    }

    @PostMapping(value = "/save")
    public String saveUser(@RequestParam String name, @RequestParam String lastName, @RequestParam byte age,
                           @RequestParam String email, @RequestParam String password, @RequestParam Set<String> roles) {
        User user = new User(name, lastName, age, email, password);
        setRoles(roles, user);
        userService.addUser(user);
        return "redirect:/admin";
    }

    @PostMapping(value = "/edit")
    public String editUser(@RequestParam Long id, @RequestParam String name,
                           @RequestParam String lastName, @RequestParam String age,
                           @RequestParam String email, @RequestParam String password,
                           @RequestParam(required = false) Set<String> roles) {
        User user = userService.findUser(id);
        user.setName(name);
        user.setLastName(lastName);
        user.setAge(Byte.parseByte(age));
        user.setEmail(email);
        user.setPassword(password);
        if (roles != null) {
            setRoles(roles, user);
        }
        userService.updateUser(user);
        return "redirect:/admin";
    }

    private void setRoles(@RequestParam(required = false) Set<String> roles, User user) {
        user.setRoles(new HashSet<>());
        for (String s : roles) {
            if (s.equals("admin")) {
                user.getRoles().add(userService.findRoleByName("ADMIN"));
                break;
            } else {
                user.getRoles().add(userService.findRoleByName("USER"));
            }
        }
    }

    @PostMapping(value = "/delete")
    public String deleteUser(@RequestParam long id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }
}