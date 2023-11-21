package com.example.userservice.jpa;

import com.example.userservice.dto.UserDto;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<UserEntity, Long> {

    UserDto findByUserId(String userId);

    UserEntity findByEmail(String username);
}
