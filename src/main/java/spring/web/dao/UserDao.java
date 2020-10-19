package spring.web.dao;

import spring.web.model.Role;
import spring.web.model.User;

import java.util.List;

public interface UserDao {
    void addUser(User user);

    List<User> getAllUsers();

    void deleteUser(long id);

    User findUser(long id);

    User getUserByName(String name);

    Role findRoleByName(String roleName);

    void updateUser(User user);
}
