package org.northcoder.demoauthentication;

import com.google.gson.Gson;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import static org.northcoder.demoauthentication.Constants.*;

//https://sdk.amazonaws.com/java/api/latest/
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminListGroupsForUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminListGroupsForUserResponse;

/**
 *
 */
public class CognitoApi {

    // https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html
    public static String getUserTokenFromAuthCode(String code) throws MalformedURLException, IOException {
        if (code == null || code.isBlank()) {
            return null;
        }

        URL url = new URL(String.format("%s%s", SUB_DOMAIN, "/oauth2/token"));
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        String tokenReqBody = buildTokenRequestBody(code);
        conn.setRequestProperty("Content-Length", Integer.toString(tokenReqBody.length()));
        conn.setDoOutput(true);
        conn.getOutputStream().write(tokenReqBody.getBytes(StandardCharsets.UTF_8));

        StringBuilder responseBody = new StringBuilder();
        try (BufferedReader in = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                responseBody.append(inputLine);
            }
        } catch (Exception e) {
            String msg = new String(conn.getErrorStream().readAllBytes(),
                    StandardCharsets.UTF_8);
            LogManager.getRootLogger().error(msg, e);
        }

        return getToken(responseBody.toString());
    }

    private static String buildTokenRequestBody(String code) {
        StringBuilder sb = new StringBuilder();
        sb.append("grant_type=authorization_code")
                .append("&client_id=").append(COGNITO_CLIENT_ID)
                .append("&redirect_uri=").append(COGNITO_LOGIN_REDIRECT)
                .append("&code=").append(code);
        return sb.toString();
    }

    private static String getToken(String json) {
        Gson gson = new Gson();
        Map<String, Object> map = new HashMap<>();
        map = gson.fromJson(json, map.getClass());
        String token = null;
        if (map.get("id_token") != null) {
            token = (String) map.get("id_token");
        }
        return token;
    }

    // Most of the methods needed to perform Cognito admin functions are documented here:
    // https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/services/cognitoidentityprovider/CognitoIdentityProviderClient.html
    private static CognitoIdentityProviderClient client;

    public static List<User> getUsers() {

        // Credentials are assumed to be in the standard credentials/config 
        // file location (e.g. in ".aws" under the user's home directory).
        client = CognitoIdentityProviderClient.builder()
                .region(Region.of(AWS_REGION))
                .credentialsProvider(ProfileCredentialsProvider.builder()
                        //.profileFile(pf) - for custom file location
                        .profileName("demo_cognito")
                        .build())
                .build();

        ListUsersResponse resp = client.listUsers(
                ListUsersRequest.builder()
                        .userPoolId(AWS_USER_POOL_ID)
                        .limit(50)
                        .build());

        List<User> users = new ArrayList();
        users.addAll(resp.users().stream().map(u -> convertCognitoUser(u))
                .collect(Collectors.toList()));
        return users;
    }

    private static User convertCognitoUser(UserType awsCognitoUser) {

        User user = new User();

        for (AttributeType userAttribute : awsCognitoUser.attributes()) {
            switch (userAttribute.name()) {
                case "preferred_username":
                    user.setPreferredName(userAttribute.value());
                    break;
                case "sub":
                    user.setUserID(userAttribute.value());
                    break;
                case "given_name":
                    user.setGivenName(userAttribute.value());
                    break;
                case "family_name":
                    user.setFamilyName(userAttribute.value());
                    break;
                case "email":
                    user.setEmail(userAttribute.value());
                    break;
                case "email_verified":
                    user.setEmailIsVerified((userAttribute.value()
                            .equalsIgnoreCase("true")));
                    break;
            }
        }
        user.getCognitoGroupNames().addAll(getGroupsForUser(awsCognitoUser));
        user.setAppRolesFromCognitoGroupNames();
        return user;
    }

    private static List<String> getGroupsForUser(UserType awsCognitoUser) {
        AdminListGroupsForUserResponse resp = client.adminListGroupsForUser(
                AdminListGroupsForUserRequest.builder()
                        .userPoolId(AWS_USER_POOL_ID)
                        .username(awsCognitoUser.username())
                        .limit(50)
                        .build());

        List<String> groupNames = new ArrayList();
        groupNames.addAll(resp.groups().stream().map(u -> u.groupName())
                .collect(Collectors.toList()));
        return groupNames;
    }

}
