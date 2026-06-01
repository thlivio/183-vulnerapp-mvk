package ch.bbw.m183.vulnerapp.controller;

import ch.bbw.m183.vulnerapp.datamodel.UserEntity;
import ch.bbw.m183.vulnerapp.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')") // All endpoints in this controller require ADMIN role
public class AdminController {

	private final AdminService adminService;

	@PostMapping("/create")
	public UserEntity createUser(@RequestBody UserEntity newUser) {
		return adminService.createUser(newUser);
	}

	@GetMapping("/users")
	public Page<UserEntity> getUsers(Pageable pageable) {
		return adminService.getUsers(pageable);
	}

	@DeleteMapping("/delete/{username}")
	public void deleteUser(@PathVariable String username) {
		adminService.deleteUser(username);
	}
}


