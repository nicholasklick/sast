// Mass Assignment vulnerabilities in Java

import javax.servlet.http.*;
import java.lang.reflect.*;
import java.util.Map;
import java.util.HashMap;

public class MassAssignment {

    // Vulnerable model with sensitive properties
    public static class User {
        private String username;
        private String email;
        private String password;
        private boolean isAdmin = false;  // Sensitive!
        private double balance = 0;       // Sensitive!
        private String role = "user";     // Sensitive!

        // Getters and setters
        public void setUsername(String username) { this.username = username; }
        public void setEmail(String email) { this.email = email; }
        public void setPassword(String password) { this.password = password; }
        public void setIsAdmin(boolean isAdmin) { this.isAdmin = isAdmin; }
        public void setBalance(double balance) { this.balance = balance; }
        public void setRole(String role) { this.role = role; }
    }

    // Test 1: Reflection-based property binding
    public User createUserReflection(HttpServletRequest request) throws Exception {
        User user = new User();
        // VULNERABLE: Binding all request parameters via reflection
        for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
            String propertyName = entry.getKey();
            String value = entry.getValue()[0];

            String setterName = "set" + propertyName.substring(0, 1).toUpperCase() + propertyName.substring(1);
            try {
                Method setter = User.class.getMethod(setterName, String.class);
                setter.invoke(user, value);
            } catch (NoSuchMethodException e) {
                // Try boolean
                try {
                    Method setter = User.class.getMethod(setterName, boolean.class);
                    setter.invoke(user, Boolean.parseBoolean(value));
                } catch (NoSuchMethodException ignored) {}
            }
        }
        return user;
    }

    // Test 2: BeanUtils.populate
    public User createUserBeanUtils(HttpServletRequest request) throws Exception {
        User user = new User();
        // VULNERABLE: BeanUtils binds all parameters
        // org.apache.commons.beanutils.BeanUtils.populate(user, request.getParameterMap());
        return user;
    }

    // Test 3: Jackson ObjectMapper without @JsonIgnore
    public User createUserJson(String json) throws Exception {
        // VULNERABLE: All JSON properties deserialized
        // ObjectMapper mapper = new ObjectMapper();
        // return mapper.readValue(json, User.class);
        return new User();
    }

    // Test 4: Spring @ModelAttribute without @InitBinder
    // @PostMapping("/users")
    // public String createUser(@ModelAttribute User user) {
    //     // VULNERABLE: All form fields bound
    //     userService.save(user);
    //     return "redirect:/users";
    // }

    // Test 5: Map-based property setting
    public User createUserFromMap(Map<String, Object> data) {
        User user = new User();
        // VULNERABLE: All map entries applied
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            try {
                Field field = User.class.getDeclaredField(entry.getKey());
                field.setAccessible(true);
                field.set(user, entry.getValue());
            } catch (Exception ignored) {}
        }
        return user;
    }

    // Test 6: Constructor injection via parameter names
    public User createUserConstructor(HttpServletRequest request) {
        // VULNERABLE: If constructor parameters match request params
        String username = request.getParameter("username");
        String email = request.getParameter("email");
        String isAdmin = request.getParameter("isAdmin");  // Dangerous!

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        if (isAdmin != null) {
            user.setIsAdmin(Boolean.parseBoolean(isAdmin));
        }
        return user;
    }

    // Test 7: JSTL/JSP EL expression injection
    // <c:forEach items="${param}" var="p">
    //     <c:set target="${user}" property="${p.key}" value="${p.value}"/>
    // </c:forEach>
}
