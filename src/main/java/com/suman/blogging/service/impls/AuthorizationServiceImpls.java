package com.suman.blogging.service.impls;

import com.suman.blogging.bean.request.LoginCredentials;
import com.suman.blogging.bean.request.UserRequest;
import com.suman.blogging.bean.response.JwtResponse;
import com.suman.blogging.bean.response.UserResponse;
import com.suman.blogging.entity.User;
import com.suman.blogging.exception.AlreadyExistsException;
import com.suman.blogging.exception.InvalidTokenException;
import com.suman.blogging.exception.NotFoundException;
import com.suman.blogging.helper.FileCRUD;
import com.suman.blogging.mapper.UserMapper;
import com.suman.blogging.repository.UserRepository;
import com.suman.blogging.security.JwtUtils;
import com.suman.blogging.security.LoggedUser;
import com.suman.blogging.security.invalidatetoken.TokenBlackListService;
import com.suman.blogging.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.*;

import static com.suman.blogging.helper.FileConfig.IMAGE_ALLOWED_FORMATS;
import static com.suman.blogging.helper.FileConfig.IMAGE_MAX_FILE_SIZE;

@Service
@RequiredArgsConstructor
public class AuthorizationServiceImpls implements UserService {

    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;
    private final TokenBlackListService tokenBlacklistService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final FileCRUD fileCRUD;

    @Override
    public boolean createUser(User user) {
        validateUserUniqueness(user);
            User mappedUser = userMapper.mapUserRegisterData(user);
            userRepository.save(mappedUser);
       return true;
        }


    @Override
    public JwtResponse loginUser(LoginCredentials loginCredentials) {
        try {
            Optional<User> user = findUserByUsernameOrPhoneNumber(loginCredentials.getUserName());
        if (user.isEmpty()){
            throw new UsernameNotFoundException("user not found");
        }
            Authentication authentication = authenticateUser(loginCredentials);
        User userDetails = (User) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails.getUsername(), userDetails.getUserId());
        String email = userDetails.getEmail();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        String refreshToken = jwtUtils.generateJwtRefreshToken(userDetails.getUsername(),userDetails.getUserId(),roles);

        return new JwtResponse(200,jwt,refreshToken,email, roles.get(0));
        } catch (UsernameNotFoundException e) {
            throw new NotFoundException("User not found");
        } catch (BadCredentialsException e) {
            System.out.println("Invalid credentials: " + e.getMessage());
            throw new RuntimeException("Invalid username or password");
        } catch (AuthenticationException e) {
            System.out.println("Authentication failed: " + e.getMessage());
            throw new RuntimeException("Authentication failed");
        }
    }

    @Override
    public String logOutUser(String token) {
        String jwt = token.substring(7);
        if (jwtUtils.validateJwtToken(jwt)) {
            if (tokenBlacklistService.isTokenBlacklisted(jwt)) {
                throw new InvalidTokenException("Token has already been invalidated");
            }
            tokenBlacklistService.blacklistToken(jwt);

            return "Logged out successfully!";
        } else {
           throw new NotFoundException("Token not found");
        }
    }

    @Override
    public UserResponse getUserById() {
        Long userId= LoggedUser.findUser().getUserId();
        User byId = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("no data"));
        String imagePath = byId.getImagePath();
        byId.setImagePath(fileCRUD.getImageUrl(imagePath,"UserImage"));

       return userMapper.mapUserFetch(byId);
    }

    @Override
    public JwtResponse createRefreshToken(String refreshToken) {
        try {
            boolean checkRefreshTokenValidation = jwtUtils.validateJwtRefreshToken(refreshToken);
            if (!checkRefreshTokenValidation){
                throw new InvalidTokenException("Token is invalid");
            }
            if (tokenBlacklistService.isTokenBlacklisted(refreshToken)) {
                throw new InvalidTokenException("Token has already been invalidated");
            }
            String username = jwtUtils.extractUsername(refreshToken);
            Long userId=jwtUtils.extractUserId(refreshToken);
            String jwtToken=jwtUtils.generateJwtToken(username,userId);
            List<String> roles=jwtUtils.extractRoles(refreshToken);
            String newRefreshToken=jwtUtils.generateJwtRefreshToken(username,userId,roles);

            return new JwtResponse(200,jwtToken,newRefreshToken,username, roles.get(0));
        } catch (InvalidTokenException e) {
            throw new InvalidTokenException("Invalid refresh token: " + e.getMessage());
        }
    }

    @Override
    public boolean createUserWithImageUpload(User user, MultipartFile file) {
        validateUserUniqueness(user);
        validateFile(file);
        String imageName = generateImageName();
        fileCRUD.uploadImage(file,imageName,"UserImage");
        user.setImagePath(imageName);
        User mappedUser = userMapper.mapUserRegisterData(user);
        userRepository.save(mappedUser);
        return true;
    }

    @Override
        public boolean updateUser(UserRequest userRequest) {
            Long userId = LoggedUser.findUser().getUserId();
            User existingUser = userRepository.findById(userId)
                    .orElseThrow(() -> new NotFoundException("User not found"));
            updateUserFields(userRequest, existingUser);

            userRepository.save(existingUser);
            return true;
        }

    @Override
    public boolean updateUserImage(MultipartFile userImage) {
        validateFile(userImage);
        Long userId=LoggedUser.findUser().getUserId();
        User user=userRepository.findById(userId).orElseThrow(()->new NotFoundException("User not found"));
        String oldImagePath = user.getImagePath();
        String imageName = generateImageName();
        String imagePath = fileCRUD.updateUserImage(userImage, oldImagePath, imageName, "UserImage");
        user.setImagePath(imagePath);
        userRepository.save(user);
        return true;
    }

    /**
     * Updates the fields of an existing user based on the provided user request.
     *
     * @param userRequest contains the new user details.
     * @param existingUser the user entity to be updated.
     */
    private void updateUserFields(UserRequest userRequest, User existingUser) {
        if (userRequest.getFirstName() != null) {
            existingUser.setFirstname(userRequest.getFirstName());
        }
        if (userRequest.getLastName() != null) {
            existingUser.setLastname(userRequest.getLastName());
        }
        if (userRequest.getPhoneNumber() != null) {
            updatePhoneNumber(userRequest, existingUser);
        }
        if (userRequest.getNewPassword() != null && userRequest.getOldPassword() != null) {
            updatePassword(userRequest, existingUser);
        }
    }

    /**
     * Updates the phone number of an existing user if it is not already in use.
     *
     * @param userRequest contains the new phone number.
     * @param existingUser the user entity to be updated.
     */
    private void updatePhoneNumber(UserRequest userRequest, User existingUser) {
        if (!userRepository.existsByPhoneNumber(userRequest.getPhoneNumber())) {
            existingUser.setPhoneNumber(userRequest.getPhoneNumber());
        }
        else {
            throw new AlreadyExistsException("Phone Number Already Exists");
        }
    }


    /**
     * Updates the password of an existing user if the old password matches.
     *
     * @param userRequest contains the old and new passwords.
     * @param existingUser the user entity to be updated.
     */
    private void updatePassword(UserRequest userRequest, User existingUser) {
        if (bCryptPasswordEncoder.matches(userRequest.getOldPassword(), existingUser.getPassword())) {
            existingUser.setPassword(bCryptPasswordEncoder.encode(userRequest.getNewPassword()));
        }
        else {
            throw new InvalidTokenException("Password doesn't match with old password");
        }
    }



    /**
     * Validates the given file for emptiness, size, and format.
     *
     * @param file the file to be validated
     * @throws IllegalArgumentException if the file is empty, exceeds size limit, or has an unsupported format
     */
    private void validateFile(MultipartFile file) {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }

        if (file.getSize() > IMAGE_MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File size exceeds the limit of 5MB");
        }

        String contentType = file.getContentType();
        if (!isFormatAllowed(contentType)) {
            throw new IllegalArgumentException("File format not allowed. Allowed formats are JPEG, PNG, and GIF");
        }
    }

    /**
     * Checks if the given file format is allowed.
     *
     * @param contentType the content type of the file
     * @return true if the format is allowed, false otherwise
     */
    private boolean isFormatAllowed(String contentType) {
        for (String format : IMAGE_ALLOWED_FORMATS) {
            if (format.equals(contentType)) {
                return true;
            }
        }
        return false;
    }


    /**
     * Generates a unique image name using a UUID and the file's original extension.
     *
     * @return the generated unique image name
     */
    private String generateImageName() {
        return UUID.randomUUID().toString();
    }




    /**
     * Validates whether the user's email or phone number already exists in the database.
     *
     * @param user The user to be validated.
     * @throws AlreadyExistsException if the email or phone number already exists.
     */
    private void validateUserUniqueness(User user) {
        if
        (userRepository.existsByEmailOrPhoneNumber(user.getEmail(), user.getPhoneNumber()))
        {
            throw new AlreadyExistsException("Email or phone number already exists");
        }
    }




    /**
     * Finds a user by email or phone number.
     *
     * @param usernameOrPhoneNumber The username or phone number provided for login.
     * @throws NotFoundException if the  phone number format is incorrect.
     * @return An optional User object.
     */
    private Optional<User> findUserByUsernameOrPhoneNumber(String usernameOrPhoneNumber) {
        if (usernameOrPhoneNumber.contains("@")) {
            return userRepository.findByEmail(usernameOrPhoneNumber);
        } else {
            try {
                Long phoneNumber = Long.parseLong(usernameOrPhoneNumber);
                return userRepository.findByPhoneNumber(phoneNumber);
            } catch (NumberFormatException e) {
                throw new NotFoundException("Number mismatched: " + usernameOrPhoneNumber);
            }
        }
    }

    /**
     * Authenticates a user with the provided login credentials.
     *
     * @param loginCredentials The login credentials containing username and password.
     * @return The authentication object if authentication is successful.
     */
    private Authentication authenticateUser(LoginCredentials loginCredentials) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginCredentials.getUserName(), loginCredentials.getPassword()));
    }
}
