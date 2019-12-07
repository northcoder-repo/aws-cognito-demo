package org.northcoder.demoauthentication;

/**
 *
 */
public class Constants {

    //
    // In production you would probably NOT keep some of these values here - they 
    // would more likely be stored outside of the source code.
    //
    public static final String AWS_REGION = "?" // example: "us-east-1";
    public static final String AWS_USER_POOL_ID = AWS_REGION + "_????????";
    public static final String COGNITO_CLIENT_ID = "????...????";

    // used for Cognito callbacks (PRD = production; TST = testing):
    private static final String DOMAIN_PRD = "https://your_domain.com";
    private static final String DOMAIN_TST = "http://localhost:7000";
    public static final String DOMAIN = DOMAIN_TST;

    // subdomain is always this - no difference between PRD and TST, in this demo:
    public static final String SUB_DOMAIN = "https://auth.your_domain.com";

    public static final String LOGIN_REDIRECT_ENDPOINT = "/log-in-result";
    public static final String COGNITO_LOGIN_REDIRECT = DOMAIN + LOGIN_REDIRECT_ENDPOINT;

    public static final String LOGOUT_REDIRECT_ENDPOINT = "/log-out-result";
    public static final String COGNITO_LOGOUT_REDIRECT = DOMAIN + LOGOUT_REDIRECT_ENDPOINT;

    public static final String PUBLIC_PATH = "/public";
    public static final String WELCOME_PATH = "/welcome";
    public static final String SIGNED_IN_PATH = "/signed-in";
    public static final String SECURED_PATH = "/secured";
    public static final String ADMIN_PATH = "/admin";

    public static final String UNAUTHORIZED = "You are not authorized to access this resource.";
}
