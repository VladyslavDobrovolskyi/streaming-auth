package com.project.streaming_auth.repos;

import com.project.streaming_auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String email);

    boolean existsByUsername(String username);
}