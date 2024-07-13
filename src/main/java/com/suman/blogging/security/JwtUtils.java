package com.suman.blogging.security;

import com.suman.blogging.exception.InvalidTokenException;
import com.suman.blogging.security.invalidatetoken.TokenBlackListService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import io.jsonwebtoken.security.SignatureException;

@Component
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class JwtUtils {

    @Autowired
    @Lazy
    private  TokenBlackListService tokenBlacklistService;

    @Value("${AppName.app.jwtSecret}")
    private String jwtSecret;
    @Value("${AppName.app.RefreshJwtSecret}")
    private String jwtRefreshSecret;

    @Value("${AppName.app.expiration}")
    private long jwtExpirationMs;
    @Value("${AppName.app.jwtRefreshExpirationMs}")
    private long jwtRefreshExpirationMs;


    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }



    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody().getSubject();
    }


    public String generateJwtToken(String username,Long userId) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", userId);

        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(username)
                .setIssuedAt((new Date(System.currentTimeMillis())))
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class));
    }

    public String generateJwtRefreshToken(String username,Long userId, List<String> roles) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", userId);
        extraClaims.put("roles", roles);
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(username)
                .setIssuedAt((new Date(System.currentTimeMillis())))
                .setExpiration(new Date((new Date()).getTime() + jwtRefreshExpirationMs))
                .signWith(getSignInKeyRefresh(), SignatureAlgorithm.HS256)
                .compact();
    }
    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> {
            List<?> roles = claims.get("roles", List.class);
            return roles.stream().map(Object::toString).collect(Collectors.toList());
        });
    }

    public boolean validateJwtToken(
            String authToken) throws SignatureException, MalformedJwtException, ExpiredJwtException, UnsupportedJwtException, IllegalArgumentException {
        try {

            Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(authToken);
            if (tokenBlacklistService.isTokenBlacklisted(authToken)) {
                throw new InvalidTokenException("Token has been invalidated");
            }
            return true;
        } catch (SignatureException e) {
            System.out.println("Invalid JWT signature: {}"+e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT token: {}"+e.getMessage());
            throw e;
        } catch (ExpiredJwtException e) {
            System.out.println("JWT token is expired: {}"+e.getMessage());
            throw e;
        }  catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid JWT token: " + e.getMessage());
        }
    }

    public boolean validateJwtRefreshToken(
            String authToken) throws SignatureException, MalformedJwtException, ExpiredJwtException, UnsupportedJwtException, IllegalArgumentException {
        try {
            Jwts.parserBuilder().setSigningKey(getSignInKeyRefresh()).build().parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            System.out.println("Invalid JWT signature: {}"+e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT token: {}"+e.getMessage());
            throw e;
        } catch (ExpiredJwtException e) {
            System.out.println("JWT token is expired: {}"+e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            System.out.println("JWT token is unsupported: {}"+e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            System.out.println("JWT claims string is empty: {}"+ e.getMessage());
            throw e;
        }
    }


    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Key getSignInKeyRefresh(){
        byte[] keyBytes = Decoders.BASE64.decode(jwtRefreshSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
