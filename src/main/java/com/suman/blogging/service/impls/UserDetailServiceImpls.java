package com.suman.blogging.service.impls;

import com.suman.blogging.entity.User;
import com.suman.blogging.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailServiceImpls implements UserDetailsService {
    private final UserRepository userRepo;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user;

        if (username.contains("@")) {
            // It's an email
            user = userRepo.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + username));
        } else {
            // It's a phone number
            try {
                Long phoneNumber = Long.parseLong(username);
                user = userRepo.findByPhoneNumber(phoneNumber)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found with phone number: " + username));
            } catch (NumberFormatException e) {
                throw new UsernameNotFoundException("Invalid login credential: " + username);
            }
        }
        return user;
    }
}
