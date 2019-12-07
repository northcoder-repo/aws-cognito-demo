package org.northcoder.demoauthentication;

import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import com.google.gson.annotations.SerializedName;
import io.javalin.core.security.Role;
import java.text.Collator;

/**
 *
 */
public class User implements Comparable<User> {

    @SerializedName(value = "cognito:username")
    private String userID;
    @SerializedName(value = "preferred_username")
    private String preferredName;
    @SerializedName(value = "given_name")
    private String givenName;
    @SerializedName(value = "family_name")
    private String familyName;
    @SerializedName(value = "email")
    private String email;
    @SerializedName(value = "email_verified")
    private boolean emailIsVerified;
    @SerializedName(value = "cognito:groups")
    private List<String> cognitoGroupNames = new ArrayList();
    private final Set<Role> assignedRoles = new HashSet();

    public String getUserID() {
        return userID;
    }

    public String getAbbrevUserID() {
        return userID.substring(0, 4) + "..."
                + userID.substring(userID.length() -4, userID.length());
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String getPreferredName() {
        return preferredName;
    }

    public void setPreferredName(String preferredName) {
        this.preferredName = preferredName;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean getEmailIsVerified() {
        return emailIsVerified;
    }

    public void setEmailIsVerified(boolean emailIsVerified) {
        this.emailIsVerified = emailIsVerified;
    }

    public List<String> getCognitoGroupNames() {
        return cognitoGroupNames;
    }

    public void setCognitoGroupNames(List<String> cognitoGroupNames) {
        this.cognitoGroupNames = cognitoGroupNames;
    }

    public void setAppRolesFromCognitoGroupNames() {
        // map the assigned Cognito group names to UserRole enum values:
        if (cognitoGroupNames != null) {
            cognitoGroupNames.forEach((groupName) -> {
                assignedRoles.add(UserRole.get(groupName));
            });
        }
    }
    
    public void setLoggedInRole() {
        assignedRoles.add(UserRole.SIGNED_IN);
    }

    public Set<Role> getAssignedRoles() {
        return assignedRoles;
    }

    @Override
    public int compareTo(User other) {
        int result = compareUsingCollator(this.getPreferredName(), other.getPreferredName());
        if (result != 0) {
            return result;
        }
        return compareUsingCollator(this.getFamilyName(), other.getFamilyName());
    }
    
    private static int compareUsingCollator(String string, String other) {
        if (string == null && other == null) {
            return 0;
        }
        if (string == null) {
            return 1;
        }
        if (other == null) {
            return -1;
        }
        final Collator collator = Collator.getInstance();
        // consider base letters, but ignore diacritics and upper/lower case:
        collator.setStrength(Collator.PRIMARY);
        // accented characters are not decomposed:
        collator.setDecomposition(Collator.NO_DECOMPOSITION);
        return collator.compare(string, other);
    }
}
