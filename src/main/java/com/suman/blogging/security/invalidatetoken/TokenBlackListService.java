package com.suman.blogging.security.invalidatetoken;

import com.suman.blogging.security.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenBlackListService {
    private Map<String, Date> blacklistedTokens = new ConcurrentHashMap<>();

    @Autowired
    @Lazy
    private JwtUtils jwtUtils;

    @Scheduled(fixedRate = 3600000) // Run every hour
    public void cleanupExpiredTokens() {
        Date now = new Date();
        blacklistedTokens.entrySet().removeIf(entry -> entry.getValue().before(now));
    }
    public void blacklistToken(String token) {
        Date expiryDate = jwtUtils.extractExpiration(token);
        blacklistedTokens.put(token, expiryDate);
    }
    public boolean isTokenBlacklisted(String token) {
        if (blacklistedTokens.containsKey(token)) {
            Date expiryDate = blacklistedTokens.get(token);
            if (expiryDate.before(new Date())) {
                blacklistedTokens.remove(token);
                return false;
            }
            return true;
        }
        return false;
    }


}
