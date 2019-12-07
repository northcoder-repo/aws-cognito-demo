package org.northcoder.demoauthentication;

import com.google.gson.Gson;
import io.javalin.http.Context;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import static org.northcoder.demoauthentication.Constants.*;

/**
 *
 */
public class Controller {

    public static Map<String, Object> buildWelcomeModel(Context ctx) {
        // See documentation for the "state" request parameter here:
        // https://docs.aws.amazon.com/cognito/latest/developerguide/login-endpoint.html
        String sessionID = ctx.req.getSession().getId();
        String uuid = UUID.randomUUID().toString();
        ctx.sessionAttribute("sessionUuid", uuid);
        String state = format(HMAC.calcHmacSha256(uuid, sessionID));

        Map<String, Object> model = new HashMap();

        // URLs for signin/signout/signup actions:
        model.put("signInUrl", buildSignInAndSignUpUrls("/login", state));
        model.put("signUpUrl", buildSignInAndSignUpUrls("/signup", state));
        model.put("signOutUrl", buildSignOutUrl());
        // if the user is already logged in, then the user object in the
        // session will be present and well-formed.  Otherwise, null.
        model.put("user", ctx.sessionAttribute("user"));
        return model;
    }

    private static String buildSignInAndSignUpUrls(String target, String state) {
        StringBuilder sb = new StringBuilder();
        sb.append(SUB_DOMAIN).append(target);
        sb.append("?");
        sb.append("response_type=code").append("&");
        sb.append("state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8)).append("&");
        sb.append("client_id=").append(COGNITO_CLIENT_ID).append("&");
        sb.append("redirect_uri=").append(DOMAIN).append(LOGIN_REDIRECT_ENDPOINT);
        return sb.toString();
    }

    private static String buildSignOutUrl() {
        StringBuilder sb = new StringBuilder();
        sb.append(SUB_DOMAIN).append("/logout");
        sb.append("?");
        sb.append("client_id=").append(COGNITO_CLIENT_ID).append("&");
        sb.append("logout_uri=").append(DOMAIN).append(LOGOUT_REDIRECT_ENDPOINT);
        return sb.toString();
    }

    public static void handleLoginCallback(Context ctx) throws IOException {
        if (ctx.res.getStatus() != 200) {
            // something went wrong:
            LogManager.getRootLogger().error(String
                    .format("Cognito error during login callback - status %s.",
                            ctx.res.getStatus()));
            ctx.status(401).result(UNAUTHORIZED);
        } else {
            String savedUuid = ctx.sessionAttribute("sessionUuid");
            if (savedUuid == null) {
                // something went wrong:
                LogManager.getRootLogger().error("Saved UUID not found during login callback.");
                ctx.status(401).result(UNAUTHORIZED);
            } else {
                processLoginCallbackState(ctx, savedUuid);
            }
        }
    }

    private static void processLoginCallbackState(Context ctx, String savedUuid) throws IOException {
        // Re-calculate the "state" value (see above) using the current
        // session ID and the originally generated UUID- see if this new
        // value matches the originally calculated value:
        String sessionID = ctx.req.getSession().getId();
        String savedState = format(HMAC.calcHmacSha256(savedUuid, sessionID));
        String queryParamState = ctx.queryParam("state");
        if (queryParamState == null) {
            // something went wrong:
            LogManager.getRootLogger().error("Missing query parameter state during login callback.");
            ctx.status(401).result(UNAUTHORIZED);
        } else {
            String callbackState = format(queryParamState);
            if (callbackState.equals(savedState)) {
                processLoginCallbackCode(ctx);
            } else {
                // something went wrong:
                LogManager.getRootLogger().error("State mismatch during login callback.");
                ctx.status(401).result(UNAUTHORIZED);
            }
        }
    }
    
    private static String format(String state) {
        // The string we get back from Cognito will have any trailing
        // equals removed, and it will use "+" for spaces, and so on.
        // We adjust for those here, for the string comparison.
        while (state.endsWith("=")) {
            state = state.substring(0, state.length()-1);
        }
        return URLEncoder.encode(state, StandardCharsets.UTF_8);
    }

    private static void processLoginCallbackCode(Context ctx) throws IOException {
        String code = ctx.queryParam("code");
        String idToken = CognitoApi.getUserTokenFromAuthCode(code);
        User user = getUserInfo(idToken);
        // For a little extra security - so even the user cannot replay their own
        // login result callback URL again - and it's harder for anyone else to
        // hijack the user's logged-in session (because it has a new session ID):
        ctx.req.changeSessionId();
        // put the user object into the session context, to indicate a "logged-in" session:
        ctx.sessionAttribute("user", user);
        ctx.redirect(WELCOME_PATH, 303);
    }

    // The token is a Json Web Token (JWT) - https://tools.ietf.org/html/rfc7519
    public static User getUserInfo(String idToken) throws MalformedURLException, IOException {
        if (idToken == null || idToken.isBlank()) {
            return null;
        }
        String[] split_string = idToken.split("\\.");
        String base64Body = split_string[1];
        String body = new String(Base64.getDecoder().decode(base64Body), StandardCharsets.UTF_8);
        Gson gson = new Gson();
        User user = gson.fromJson(body, User.class);
        user.setAppRolesFromCognitoGroupNames();
        user.setLoggedInRole();
        return user;
    }

}
