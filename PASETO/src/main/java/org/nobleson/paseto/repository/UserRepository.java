package org.nobleson.paseto.repository;

import org.nobleson.paseto.entities.AppUsers;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<AppUsers, String> {

    Optional<AppUsers> findByUsername(String username);
}
