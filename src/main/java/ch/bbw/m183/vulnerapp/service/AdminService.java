package ch.bbw.m183.vulnerapp.service;

import java.util.stream.Stream;

import ch.bbw.m183.vulnerapp.datamodel.UserEntity;
import ch.bbw.m183.vulnerapp.repository.UserRepository;
import ch.bbw.m183.vulnerapp.security.PasswordHashingService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class AdminService {

	private final PasswordHashingService passwordHashingService;
	private final UserRepository userRepository;

	public UserEntity createUser(UserEntity newUser) {
		return userRepository.save(newUser);
	}

	public Page<UserEntity> getUsers(Pageable pageable) {
		return userRepository.findAll(pageable);
	}

	public void deleteUser(String username) {
		userRepository.deleteById(username);
	}

	@EventListener(ContextRefreshedEvent.class)
	public void loadTestUsers() {
		Stream.of(new UserEntity().setUsername("admin").setFullname("Super Admin").setPassword(passwordHashingService.hashPassword("Admin@12345")).setRole("ROLE_ADMIN"),
						new UserEntity().setUsername("fuu").setFullname("Johanna Doe").setPassword(passwordHashingService.hashPassword("Fuu!12345")).setRole("ROLE_USER"))
				.forEach(this::createUser);
	}
}
