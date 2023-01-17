package com.tdev.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tdev.security.models.ERole;
import com.tdev.security.models.Role;


@Repository
public interface RoleRepository extends JpaRepository<Role, Long>{
	 Optional<Role> findByName(ERole name);
}
