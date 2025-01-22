package Portfolio.Tracker.Service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;


@Service
public class OTPService {
    private final Map<String, String> otpStorage = new ConcurrentHashMap<>();

    // Generate a 6-digit OTP
    public String generateOTP(String email) {
        String otp = String.format("%06d", new Random().nextInt(999999));
        otpStorage.put(email, otp);
        return otp;
    }

    // Verify the OTP
    public boolean verifyOTP(String email, String otp) {
        String storedOTP = otpStorage.get(email);
        return storedOTP != null && storedOTP.equals(otp);
    }

    // Clear the OTP after verification
    public void clearOTP(String email) {
        otpStorage.remove(email);
    }
}