package org.northcoder.demoauthentication;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 *
 */
public class HMAC {

    public static String calcHmacSha256(String secretKey, String message) {
        String algo = "HmacSHA256";
        byte[] hmacSha256 = null;
        try {
            Mac mac = Mac.getInstance(algo);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey
                    .getBytes(StandardCharsets.UTF_8), algo);
            mac.init(secretKeySpec);
            hmacSha256 = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(String.format("Failed to calculate %s", algo), e);
        }
        return Base64.getEncoder().encodeToString(hmacSha256);
    }
}
