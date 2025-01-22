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

    // Generate OTP Secret
    @PostMapping("/generate-otp-secret")
    public ResponseEntity<?> generateOTPSecret(Authentication auth) {
        try {
            String email = auth.getName(); // Get the authenticated user's email
            String secret = twoFactorAuthService.generateOTPSecret(email);
            return ResponseEntity.ok(Map.of("secret", secret)); // Return the OTP secret as a JSON object
        } catch (RuntimeException e) {
            logger.error("Error generating OTP secret for user: {}", auth.getName(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        }
    }

    // Verify OTP
    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOTP(Authentication auth, @RequestBody Map<String, String> request) {
        try {
            String email = auth.getName(); // Get the authenticated user's email
            String otpCode = request.get("otpCode"); // Get the OTP code from the request body

            if (otpCode == null || otpCode.isEmpty()) {
                throw new IllegalArgumentException("OTP code is required.");
            }

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

    // Setup Passkey
    @PostMapping("/setup-passkey")
    public ResponseEntity<?> setupPasskey(Authentication auth) {
        try {
            String email = auth.getName(); // Get the authenticated user's email
            boolean isPasskeyEnabled = twoFactorAuthService.setupPasskey(email);
            return ResponseEntity.ok(Map.of("success", isPasskeyEnabled)); // Return passkey setup status
        } catch (RuntimeException e) {
            logger.error("Error setting up passkey for user: {}", auth.getName(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        }
    }
    // Verify Passkey
    @PostMapping("/verify-passkey")
    public ResponseEntity<?> verifyPasskey(Authentication auth, @RequestBody Map<String, String> request) {
        try {
            String email = auth.getName(); // Get the authenticated user's email
            String passkeyResponse = request.get("passkeyResponse"); // Get the passkey response from the request body

            // Validate input
            if (passkeyResponse == null || passkeyResponse.isEmpty()) {
                throw new IllegalArgumentException("Passkey response is required.");
            }

            logger.info("Verifying passkey for user: {}", email);
            logger.debug("Passkey response provided: {}", passkeyResponse); // Debug-level logging for sensitive data

            // Verify the passkey response
            boolean isVerified = twoFactorAuthService.verifyPasskey(email, passkeyResponse);

            // Log the verification result
            logger.info("Passkey verification result for user {}: {}", email, isVerified);

            // Return a standardized JSON response
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", Map.of("isVerified", isVerified),
                    "message", isVerified ? "Passkey verified successfully!" : "Invalid passkey response."
            ));
        } catch (IllegalArgumentException e) {
            // Handle input validation errors
            logger.error("Input validation error for user {}: {}", auth.getName(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "success", false,
                    "message", e.getMessage()
            ));
        } catch (RuntimeException e) {
            // Handle runtime errors (e.g., invalid passkey response, user not found)
            logger.error("Error verifying passkey for user: {}", auth.getName(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "success", false,
                    "message", e.getMessage()
            ));
        }
    }
    // Disable Passkey
    @PostMapping("/disable-passkey")
    public ResponseEntity<?> disablePasskey(Authentication auth) {
        try {
            String email = auth.getName(); // Get the authenticated user's email
            boolean isPasskeyDisabled = twoFactorAuthService.disablePasskey(email);
            return ResponseEntity.ok(Map.of("success", isPasskeyDisabled)); // Return passkey disable status
        } catch (RuntimeException e) {
            logger.error("Error disabling passkey for user: {}", auth.getName(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        }
    }



    @GetMapping("/status")
    public ResponseEntity<?> get2FAStatus(Authentication auth) {
        try {
            String email = auth.getName();
            boolean is2FAEnabled = twoFactorAuthService.get2FAStatus(email);
            return ResponseEntity.ok(Map.of("is2FAEnabled", is2FAEnabled));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/disable")
    public ResponseEntity<?> disable2FA(Authentication auth) {
        try {
            String email = auth.getName();
            boolean isDisabled = twoFactorAuthService.disable2FA(email);
            return ResponseEntity.ok(Map.of("success", isDisabled));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        }
    }
}