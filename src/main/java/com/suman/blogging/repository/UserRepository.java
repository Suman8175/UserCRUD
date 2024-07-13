package com.suman.blogging.repository;

import com.suman.blogging.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByPhoneNumber(Long phoneNumber);
    boolean existsByPhoneNumber(Long phoneNumber);

    boolean existsByEmailOrPhoneNumber(String email, Long phoneNumber);
}
