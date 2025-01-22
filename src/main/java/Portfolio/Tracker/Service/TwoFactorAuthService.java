package Portfolio.Tracker.Service;

import Portfolio.Tracker.Entity.User;
import Portfolio.Tracker.Repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TwoFactorAuthService {

    private static final Logger logger = LoggerFactory.getLogger(TwoFactorAuthService.class);

    @Autowired
    private UserRepository userRepository;

    private final GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();

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

            GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
            String secret = key.getKey();

            logger.info("Generated OTP secret: {}", secret);

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
                throw new RuntimeException("OTP secret not found for user: " + email);
            }

            logger.info("OTP secret for user {}: {}", email, secret);
            logger.info("OTP code to verify: {}", otpCode);

            // Convert the OTP code to an integer
            int otp = Integer.parseInt(otpCode);

            // Verify the OTP code
            boolean isVerified = googleAuthenticator.authorize(secret, otp);

            logger.info("OTP verification result for user {}: {}", email, isVerified);
            return isVerified;
        } catch (NumberFormatException e) {
            logger.error("Invalid OTP code format for user: {}", email, e);
            throw new RuntimeException("Invalid OTP code format: " + otpCode, e);
        } catch (Exception e) {
            logger.error("Error verifying OTP for user: {}", email, e);
            throw new RuntimeException("Failed to verify OTP: " + e.getMessage(), e);
        }
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
}