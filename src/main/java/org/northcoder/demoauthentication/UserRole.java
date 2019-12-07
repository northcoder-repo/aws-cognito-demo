package org.northcoder.demoauthentication;

import java.util.Map;
import java.util.HashMap;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import io.javalin.core.security.Role;

/**
 *
 */
public enum UserRole implements Role {

    // these roles need to have names which exactly match the names
    // of Cognito user groups:
    AUTHORIZED("authorized"),
    ADMIN("admin"),
    // this role does not exist in Cognito.
    SIGNED_IN("signed-in");

    private static final Map<String, UserRole> ENUM_MAP;

    UserRole(String userRoleName) {
        this.userRoleName = userRoleName;
    }

    private final String userRoleName;

    public String getUserRoleName() {
        return this.userRoleName;
    }

    static {
        Map<String, UserRole> map = new HashMap();
        for (UserRole instance : UserRole.values()) {
            map.put(instance.getUserRoleName(), instance);
        }
        ENUM_MAP = Collections.unmodifiableMap(map);
    }

    public static UserRole get(String name) {
        return ENUM_MAP.get(name);
    }

    public static Set<Role> getSecuredRoles() {
        Set<Role> securedRoles = new HashSet();
        // only one right now, but there could be more:
        securedRoles.add(UserRole.AUTHORIZED);
        return securedRoles;
    }

    public static Set<Role> getSignedInRole() {
        Set<Role> signedInRoles = new HashSet();
        signedInRoles.add(UserRole.SIGNED_IN);
        return signedInRoles;
    }

    public static Set<Role> getAdminRole() {
        Set<Role> adminRoles = new HashSet();
        adminRoles.add(UserRole.ADMIN);
        return adminRoles;
    }

    public static boolean accessAllowed(User user, Set<Role> permittedRoles) {
        if (permittedRoles == null || permittedRoles.isEmpty()) {
            // resource has no access restrictions:
            return true;
        }
        // user is not logged in, but the resource has access restrictions:
        if (user == null) {
            return false;
        }
        // check if any of the user's roles are in the set of permitted roles:
        if (permittedRoles.stream().anyMatch(user.getAssignedRoles()::contains)) {
            return true;
        }
        // admins can do anything:
        if (user.getAssignedRoles().contains(UserRole.ADMIN)) {
            return true;
        }
        return false;
    }

}
