package ch.bbw.m183.vulnerapp.controller;

import java.security.Principal;

import ch.bbw.m183.vulnerapp.datamodel.UserEntity;
import ch.bbw.m183.vulnerapp.repository.UserRepository;
import ch.bbw.m183.vulnerapp.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;
	private final UserRepository userRepository;

	@GetMapping("/whoami")
	public UserEntity whoami(Principal principal) {
		// Return current authenticated user from session/principal
		return userRepository.findById(principal.getName()).orElseThrow();
	}

	@PostMapping("/fakelogin")
	public UserEntity fakelogin(@RequestParam String username, @RequestParam String password) {
		return userService.whoami(username, password);
	}

	@GetMapping("/fakelogout")
	public void fakelogout() {
		// does absolutely nothing
	}
}
