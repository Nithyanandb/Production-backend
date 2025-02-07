package Portfolio.Tracker.Service;

import Portfolio.Tracker.Entity.User;
import Portfolio.Tracker.Repository.UserRepository;
import com.github.benmanes.caffeine.cache.Cache;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import org.apache.commons.codec.binary.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.TimeUnit;

@Service
public class TwoFactorAuthService {

    private static final Logger logger = LoggerFactory.getLogger(TwoFactorAuthService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private Cache<String, String> otpCache; // Cache for storing OTP codes

    private final GoogleAuthenticator googleAuthenticator;

    public TwoFactorAuthService() {
        GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
                .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(30)) // 30-second time steps
                .setWindowSize(3) // Allow a window of 3 time steps for OTP validation
                .build();
        this.googleAuthenticator = new GoogleAuthenticator(config);
    }

    /**
     * Generates an OTP secret for the user and saves it in the database.
     *
     * @param email The email of the user.
     * @return The generated OTP secret.
     * @throws RuntimeException If the user is not found or an error occurs.
     */
    @Transactional
    public String generateOTPSecret(String email) {
        try {
            logger.info("Generating OTP secret for user with email: {}", email);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            // Generate a new OTP secret
            GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
            String secret = key.getKey();

            logger.info("Generated OTP secret: {}", secret);

            // Save the OTP secret to the user entity
            user.setOtpSecret(secret);
            userRepository.save(user);

            logger.info("OTP secret saved successfully for user: {}", email);
            return secret;
        } catch (Exception e) {
            logger.error("Error generating OTP secret for user: {}", email, e);
            throw new RuntimeException("Failed to generate OTP secret: " + e.getMessage(), e);
        }
    }

    /**
     * Generates an OTP code using the provided secret and caches it.
     *
     * @param secret The OTP secret.
     * @return The generated OTP code.
     * @throws RuntimeException If an error occurs during OTP generation.
     */
    public String generateAndCacheOTP(String secret) {
        try {
            // Check if the OTP is already cached
            String cachedOtp = otpCache.getIfPresent(secret);
            if (cachedOtp != null) {
                logger.info("Retrieved OTP from cache for secret: {}", secret);
                return cachedOtp;
            }

            // Generate the OTP code
            long timeWindow = System.currentTimeMillis() / 30000; // 30-second window
            byte[] key = new Base32().decode(secret); // Decode the Base32-encoded secret
            byte[] data = new byte[8];
            for (int i = 8; i-- > 0; timeWindow >>>= 8) {
                data[i] = (byte) timeWindow;
            }

            // Generate HMAC-SHA1 hash
            SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);

            // Extract the OTP code
            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset + 1] & 0xFF) << 16) |
                    ((hash[offset + 2] & 0xFF) << 8) |
                    (hash[offset + 3] & 0xFF);

            int otp = binary % 1000000; // 6-digit OTP
            String otpCode = String.format("%06d", otp);

            // Cache the OTP code
            otpCache.put(secret, otpCode);
            logger.info("Generated and cached OTP code for secret: {}", secret);

            return otpCode;
        } catch (Exception e) {
            logger.error("Error generating OTP code: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate OTP code: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies the OTP code provided by the user.
     *
     * @param email   The email of the user.
     * @param otpCode The OTP code to verify.
     * @return True if the OTP code is valid, false otherwise.
     * @throws RuntimeException If the user is not found, the OTP secret is not set, or an error occurs.
     */
    @Transactional(readOnly = true)
    public boolean verifyOTP(String email, String otpCode) {
        try {
            logger.info("Verifying OTP for user with email: {}", email);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            String secret = user.getOtpSecret();
            if (secret == null) {
                logger.error("OTP secret not found for user: {}", email);
                throw new RuntimeException("OTP secret not found for user: " + email);
            }

            logger.info("OTP secret for user {}: {}", email, secret);
            logger.info("OTP code to verify: {}", otpCode);

            // Convert the OTP code to an integer
            int otp;
            try {
                otp = Integer.parseInt(otpCode);
            } catch (NumberFormatException e) {
                logger.error("Invalid OTP code format for user: {}", email, e);
                throw new RuntimeException("Invalid OTP code format: " + otpCode, e);
            }

            // Generate the expected OTP code
            String expectedOtpCode = generateAndCacheOTP(secret);
            logger.info("Expected OTP code for user {}: {}", email, expectedOtpCode);

            // Verify the OTP code
            boolean isVerified = otpCode.equals(expectedOtpCode);

            if (!isVerified) {
                logger.warn("OTP verification failed for user: {}", email);
                logger.warn("Possible causes: Invalid OTP code, time synchronization issue, or incorrect secret.");
            }

            logger.info("OTP verification result for user {}: {}", email, isVerified);
            return isVerified;
        } catch (Exception e) {
            logger.error("Error verifying OTP for user: {}", email, e);
            throw new RuntimeException("Failed to verify OTP: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies the passkey response provided by the user.
     *
     * @param email          The email of the user.
     * @param passkeyResponse The passkey response to verify.
     * @return True if the passkey response is valid, false otherwise.
     * @throws RuntimeException If the user is not found or an error occurs.
     */
    @Transactional(readOnly = true)
    public boolean verifyPasskey(String email, String passkeyResponse) {
        try {
            logger.info("Verifying passkey for user with email: {}", email);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            // Validate the passkey response (this logic depends on your passkey implementation)
            boolean isVerified = validatePasskeyResponse(user, passkeyResponse);

            logger.info("Passkey verification result for user {}: {}", email, isVerified);
            return isVerified;
        } catch (Exception e) {
            logger.error("Error verifying passkey for user: {}", email, e);
            throw new RuntimeException("Failed to verify passkey: " + e.getMessage(), e);
        }
    }

    /**
     * Validates the passkey response.
     *
     * @param user            The user entity.
     * @param passkeyResponse The passkey response to validate.
     * @return True if the passkey response is valid, false otherwise.
     */
    private boolean validatePasskeyResponse(User user, String passkeyResponse) {
        // Implement your passkey validation logic here
        // For example, compare the passkey response with the stored passkey data
        // This is a placeholder implementation
        return true;
    }

    /**
     * Enables passkey authentication for the user.
     *
     * @param email The email of the user.
     * @return True if passkey is enabled successfully.
     * @throws RuntimeException If the user is not found or an error occurs.
     */
    @Transactional
    public boolean setupPasskey(String email) {
        try {
            logger.info("Setting up passkey for user with email: {}", email);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            user.setPasskeyEnabled(true);
            userRepository.save(user);

            logger.info("Passkey enabled successfully for user: {}", email);
            return true;
        } catch (Exception e) {
            logger.error("Error setting up passkey for user: {}", email, e);
            throw new RuntimeException("Failed to setup passkey: " + e.getMessage(), e);
        }
    }

    /**
     * Disables passkey authentication for the user.
     *
     * @param email The email of the user.
     * @return True if passkey is disabled successfully.
     * @throws RuntimeException If the user is not found or an error occurs.
     */
    @Transactional
    public boolean disablePasskey(String email) {
        try {
            logger.info("Disabling passkey for user with email: {}", email);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            user.setPasskeyEnabled(false);
            userRepository.save(user);

            logger.info("Passkey disabled successfully for user: {}", email);
            return true;
        } catch (Exception e) {
            logger.error("Error disabling passkey for user: {}", email, e);
            throw new RuntimeException("Failed to disable passkey: " + e.getMessage(), e);
        }
    }

    /**
     * Disables 2FA for the user by removing the OTP secret.
     *
     * @param email The email of the user.
     * @return True if 2FA is disabled successfully.
     * @throws RuntimeException If the user is not found or an error occurs.
     */
    @Transactional
    public boolean disable2FA(String email) {
        try {
            logger.info("Disabling 2FA for user with email: {}", email);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            user.setOtpSecret(null);
            userRepository.save(user);

            logger.info("2FA disabled successfully for user: {}", email);
            return true;
        } catch (Exception e) {
            logger.error("Error disabling 2FA for user: {}", email, e);
            throw new RuntimeException("Failed to disable 2FA: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves the 2FA status for the user.
     *
     * @param email The email of the user.
     * @return True if 2FA is enabled, false otherwise.
     * @throws RuntimeException If the user is not found or an error occurs.
     */
    @Transactional(readOnly = true)
    public boolean get2FAStatus(String email) {
        try {
            logger.info("Retrieving 2FA status for user with email: {}", email);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            boolean is2FAEnabled = user.getOtpSecret() != null;
            logger.info("2FA status for user {}: {}", email, is2FAEnabled);
            return is2FAEnabled;
        } catch (Exception e) {
            logger.error("Error retrieving 2FA status for user: {}", email, e);
            throw new RuntimeException("Failed to retrieve 2FA status: " + e.getMessage(), e);
        }
    }
}