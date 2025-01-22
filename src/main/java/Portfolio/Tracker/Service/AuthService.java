package Portfolio.Tracker.Service;

import Portfolio.Tracker.DTO.AuthResponseDTO;
import Portfolio.Tracker.DTO.LoginRequestDTO;
import Portfolio.Tracker.DTO.RegisterRequestDTO;
import Portfolio.Tracker.DTO.VerifyOTPRequestDTO;
import Portfolio.Tracker.DTO.AuthProvider;
import Portfolio.Tracker.DTO.Role;
import Portfolio.Tracker.Entity.User;
import Portfolio.Tracker.Repository.UserRepository;
import Portfolio.Tracker.Security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final OTPService otpService; // Inject the OTPService
    private final KeyStorage keyStorage;
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String googleRedirectUri;

    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String githubClientId;

    @Value("${spring.security.oauth2.client.registration.github.redirect-uri}")
    private String githubRedirectUri;

    // Traditional Registration
    public AuthResponseDTO register(RegisterRequestDTO request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .provider(AuthProvider.LOCAL)
                .roles(Collections.singleton(Role.ROLE_USER))
                .build();

        userRepository.save(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        String token = jwtTokenProvider.generateToken(auth);

        return AuthResponseDTO.builder()
                .token(token)
                .email(user.getEmail())
                .name(user.getName())
                .message("User registered successfully")
                .build();
    }

    // Traditional Login with 2FA
    public AuthResponseDTO login(LoginRequestDTO request) {
        // Authenticate the user
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        // Fetch the user from the database
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Check if the user is using a local provider
        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new RuntimeException("Please use " + user.getProvider() + " to login");
        }

        // Check if 2FA is enabled for the user
        if (user.isPasskeyEnabled()) { // Assuming `isPasskeyEnabled` is used for 2FA
            // Generate and send OTP
            String otp = otpService.generateOTP(user.getEmail());
            sendOTP(user.getEmail(), otp); // Send OTP to the user (via email, SMS, etc.)

            // Return a response indicating OTP verification is required
            return AuthResponseDTO.builder()
                    .email(user.getEmail())
                    .message("OTP sent to your registered email. Please verify.")
                    .requiresOTP(true)
                    .build();
        }

        // If 2FA is not enabled, generate a JWT token
        String token = jwtTokenProvider.generateToken(auth);

        return AuthResponseDTO.builder()
                .token(token)
                .email(user.getEmail())
                .name(user.getName())
                .message("Login successful")
                .requiresOTP(false)
                .build();
    }

    // Verify OTP
    public AuthResponseDTO verifyOTP(VerifyOTPRequestDTO request) {
        // Fetch the user from the database
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Check if 2FA is enabled for the user
        if (!user.isPasskeyEnabled()) {
            throw new RuntimeException("2FA is not enabled for this user");
        }

        // Verify the OTP
        boolean isOTPValid = otpService.verifyOTP(request.getEmail(), request.getOtp());
        if (!isOTPValid) {
            throw new RuntimeException("Invalid OTP");
        }

        // Clear the OTP after successful verification
        otpService.clearOTP(request.getEmail());

        // Generate a JWT token
        Authentication auth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        String token = jwtTokenProvider.generateToken(auth);

        return AuthResponseDTO.builder()
                .token(token)
                .email(user.getEmail())
                .name(user.getName())
                .message("OTP verified successfully")
                .requiresOTP(false)
                .build();
    }

    // Send OTP to the user (mock implementation)
    private void sendOTP(String email, String otp) {
        // Implement logic to send OTP via email or SMS
        System.out.println("OTP for " + email + ": " + otp);
    }

    // OAuth2 URL Generators
    public String getGoogleAuthUrl() {
        return "https://accounts.google.com/o/oauth2/v2/auth?" +
                "client_id=" + googleClientId +
                "&redirect_uri=" + googleRedirectUri +
                "&response_type=code" +
                "&scope=email%20profile";
    }

    public String getGithubAuthUrl() {
        return "https://github.com/login/oauth/authorize?" +
                "client_id=" + githubClientId +
                "&redirect_uri=" + githubRedirectUri +
                "&scope=user:email";
    }


    public void logout(String token) {
        if (token != null) {
            keyStorage.removeKey(token);
        }
    }
}