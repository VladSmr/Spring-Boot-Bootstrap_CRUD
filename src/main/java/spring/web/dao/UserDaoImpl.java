package spring.web.dao;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;
import spring.web.model.Role;
import spring.web.model.User;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;

@Repository
public class UserDaoImpl implements UserDao {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public void addUser(User user) {
        entityManager.persist(user);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<User> getAllUsers() {
        return entityManager.createQuery("SELECT u FROM User u ORDER BY u.id ASC")
                .getResultList();
    }

    @Override
    public void deleteUser(long id) {
        entityManager.remove(findUser(id));
    }

    @Override
    public User findUser(long id) {
        return entityManager.find(User.class, id);
    }

    @Override
    public User getUserByName(String name) {
        User us = null;
        for (User user : getAllUsers()) {
            if (user.getName().equals(name)) {
                us = user;
            }
        }
        if (us != null) {
            return us;
        } else {
            throw new UsernameNotFoundException("msg");
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public Role findRoleByName(String role) {
        List<Role> roles = entityManager.createQuery("SELECT role from Role role").getResultList();
        for (Role someRole : roles) {
            if (someRole.getRole().equals(role)) {
                return someRole;
            }
        }
        return null;
    }

    @Override
    public void updateUser(User user) {
        entityManager.merge(user);
    }
}

