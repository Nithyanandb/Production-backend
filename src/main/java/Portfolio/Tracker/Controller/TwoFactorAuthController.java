package Portfolio.Tracker.Controller;

import Portfolio.Tracker.Service.TwoFactorAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

@RestController
@RequestMapping("/api/2fa")
public class TwoFactorAuthController {

    @Autowired
    private TwoFactorAuthService twoFactorAuthService;
    private static final Logger logger = LoggerFactory.getLogger(TwoFactorAuthController.class);
    @PostMapping("/generate-otp-secret")
    public ResponseEntity<?> generateOTPSecret(Authentication auth) {
        try {
            String email = auth.getName(); // Get the authenticated user's email
            String secret = twoFactorAuthService.generateOTPSecret(email);
            return ResponseEntity.ok(Map.of("secret", secret)); // Return the OTP secret as a JSON object
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOTP(Authentication auth, @RequestParam String otpCode) {
        try {
            String email = auth.getName(); // Get the authenticated user's email
            logger.info("Verifying OTP for user: {}", email);
            logger.info("OTP code provided: {}", otpCode);

            // Verify the OTP code
            boolean isVerified = twoFactorAuthService.verifyOTP(email, otpCode);

            // Log the verification result
            logger.info("OTP verification result for user {}: {}", email, isVerified);

            // Return a JSON object with the verification status
            return ResponseEntity.ok(Map.of(
                    "success", isVerified,
                    "message", isVerified ? "OTP verified successfully!" : "Invalid OTP code"
            ));
        } catch (NumberFormatException e) {
            // Handle invalid OTP code format (e.g., non-numeric input)
            logger.error("Invalid OTP code format for user: {}", auth.getName(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "success", false,
                    "message", "Invalid OTP code format. Please enter a 6-digit number."
            ));
        } catch (RuntimeException e) {
            // Handle other runtime errors (e.g., missing OTP secret, user not found)
            logger.error("Error verifying OTP for user: {}", auth.getName(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "success", false,
                    "message", e.getMessage()
            ));
        }
    }

    @PostMapping("/setup-passkey")
    public ResponseEntity<?> setupPasskey(Authentication auth) {
        try {
            String email = auth.getName(); // Get the authenticated user's email
            boolean isPasskeyEnabled = twoFactorAuthService.setupPasskey(email);
            return ResponseEntity.ok(isPasskeyEnabled); // Return passkey setup status
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        }
    }
}