package org.northcoder.demoauthentication;

import static io.javalin.apibuilder.ApiBuilder.*;
import io.javalin.Javalin;
import io.javalin.http.Handler;
import io.javalin.plugin.rendering.JavalinRenderer;
import io.javalin.plugin.rendering.template.JavalinThymeleaf;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Collections;
import org.apache.logging.log4j.LogManager;
import static org.northcoder.demoauthentication.Constants.*;

/**
 *
 */
public class App {

    public static void main(String[] args) {

        Javalin app = Javalin.create(config -> {
            JavalinRenderer.register(JavalinThymeleaf.INSTANCE);

            config.addStaticFiles(PUBLIC_PATH);

            config.accessManager((handler, ctx, permittedRoles) -> {
                User user = ctx.sessionAttribute("user");
                if (UserRole.accessAllowed(user, permittedRoles)) {
                    handler.handle(ctx);
                } else {
                    ctx.status(401).result(UNAUTHORIZED);
                }
            });
        }).start(7000);

        app.routes(() -> {
            // routes accessible to anyone (logged in or not):
            get("/", ROOT);
            get(WELCOME_PATH, WELCOME);
            
            // routes with role-based access restrictions:
            get(SIGNED_IN_PATH, SIGNED_IN, UserRole.getSignedInRole());
            get(SECURED_PATH, SECURED, UserRole.getSecuredRoles());
            get(ADMIN_PATH, ADMIN, UserRole.getAdminRole());
            
            // routes used by Cognito API callbacks - not directly accessed by users:
            get(LOGIN_REDIRECT_ENDPOINT, LOGIN_REDIRECT);
            get(LOGOUT_REDIRECT_ENDPOINT, LOGOUT_REDIRECT);
        });
    }

    private static final Handler ROOT = (ctx) -> {
        ctx.redirect("/welcome", 303);
    };

    private static final Handler WELCOME = (ctx) -> {
        ctx.render("welcome.html", Controller.buildWelcomeModel(ctx));
    };

    private static final Handler LOGIN_REDIRECT = (ctx) -> {
        // A callback URL is sent to Congnito during sign-on and sign-up. This
        // is the endpoint of the callback, after Cognito completes its work.
        Controller.handleLoginCallback(ctx);
    };

    private static final Handler LOGOUT_REDIRECT = (ctx) -> {
        // A callback URL is sent to Congnito during logout. This is the
        // endpoint of the callback, after Cognito completes its work.
        if (ctx.res.getStatus() != 200) {
            // something went wrong:
            LogManager.getRootLogger().error(String.format("Cognito logout error - status %s.",
                    ctx.res.getStatus()));
            ctx.status(401).result(UNAUTHORIZED);
        } else {
            ctx.req.getSession().invalidate();
            ctx.redirect("/welcome", 303);
        }
    };

    private static final Handler SIGNED_IN = (ctx) -> {
        User user = ctx.sessionAttribute("user");
        Map<String, Object> model = new HashMap();
        model.put("user", user);
        ctx.render("signed-in.html", model);
    };

    private static final Handler SECURED = (ctx) -> {
        User user = ctx.sessionAttribute("user");
        Map<String, Object> model = new HashMap();
        model.put("user", user);
        ctx.render("secured.html", model);
    };

    private static final Handler ADMIN = (ctx) -> {
        Map<String, Object> model = new HashMap();
        List<User> users = CognitoApi.getUsers();
        Collections.sort(users);
        model.put("users", users);
        ctx.render("admin.html", model);
    };

}
