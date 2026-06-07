package ch.bbw.m183.vulnerapp;

import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.CookiePolicy;
import java.net.CookieStore;
import java.net.HttpCookie;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.boot.test.context.SpringBootTest;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, properties = "server.port=8080")
class SecurityIntegrationTests {

	// Base URL for HTTP requests
	private static final String BASE_URL = "http://localhost:8080";

	private String getCsrfToken(HttpClient client) throws Exception {
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/csrf"))
				.GET()
				.build();

		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() == 200) {
			Pattern pattern = Pattern.compile("\"token\":\"([^\"]+)\"");
			Matcher matcher = pattern.matcher(response.body());
			if (matcher.find()) {
				return matcher.group(1);
			}
		}
		return null;
	}

	// ==================== Helper: Create HTTP Client with Cookie Manager ====================

	private HttpClient createHttpClientWithCookies() {
		CookieManager cookieManager = new CookieManager();
		cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
		return HttpClient.newBuilder().cookieHandler(cookieManager).build();
	}

	// ==================== Tests ====================

	@Test
	void testAnonymousHomeAccess() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 200 : "Expected 200, got " + response.statusCode();
	}

	@Test
	void testAnonymousGetBlog() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/blog")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 200 : "Expected 200, got " + response.statusCode();
	}

	@Test
	void testAnonymousPostBlogForbidden() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/blog"))
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString("{\"title\":\"Test\",\"text\":\"Test\"}"))
				.build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 403 : "Expected 403, got " + response.statusCode();
	}

	@Test
	void testAnonymousWhoamiForbidden() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/user/whoami")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 401 : "Expected 401, got " + response.statusCode();
	}

	@Test
	void testAnonymousAdminAccessForbidden() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/admin/users")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 401 : "Expected 401, got " + response.statusCode();
	}

	@Test
	void testAnonymousActuatorHealth() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/actuator/health")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 200 : "Expected 200, got " + response.statusCode();
	}

	@Test
	void testUserPostBlogWithoutCsrfForbidden() throws Exception {
		HttpClient client = createHttpClientWithCookies();

		// First get CSRF token
		String csrfToken = getCsrfToken(client);

		// Login
		HttpRequest loginRequest = HttpRequest.newBuilder(URI.create(BASE_URL + "/login"))
				.header("X-XSRF-TOKEN", csrfToken)
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString("username=fuu&password=Fuu!12345"))
				.build();
		client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

		// Try POST without CSRF
		HttpRequest postRequest = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/blog"))
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString("{\"title\":\"Test\",\"text\":\"Test\"}"))
				.build();
		HttpResponse<String> response = client.send(postRequest, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 403 : "Expected 403, got " + response.statusCode();
	}

	@Test
	void testUserGetBlogOk() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		String csrfToken = getCsrfToken(client);

		// Login
		HttpRequest loginRequest = HttpRequest.newBuilder(URI.create(BASE_URL + "/login"))
				.header("X-XSRF-TOKEN", csrfToken)
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString("username=fuu&password=Fuu!12345"))
				.build();
		client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

		// GET /api/blog
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/blog")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 200 : "Expected 200, got " + response.statusCode();
	}

	@Test
	void testUserWhoamiOk() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		String csrfToken = getCsrfToken(client);

		// Login
		HttpRequest loginRequest = HttpRequest.newBuilder(URI.create(BASE_URL + "/login"))
				.header("X-XSRF-TOKEN", csrfToken)
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString("username=fuu&password=Fuu!12345"))
				.build();
		client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

		// GET /api/user/whoami
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/user/whoami")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 200 : "Expected 200, got " + response.statusCode();
		assert response.body().contains("\"username\":\"fuu\"") : "Expected fuu in response";
	}

	@Test
	void testUserAdminAccessForbidden() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		String csrfToken = getCsrfToken(client);

		// Login
		HttpRequest loginRequest = HttpRequest.newBuilder(URI.create(BASE_URL + "/login"))
				.header("X-XSRF-TOKEN", csrfToken)
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString("username=fuu&password=Fuu!12345"))
				.build();
		client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

		// Try GET /api/admin/users
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/admin/users")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 403 : "Expected 403, got " + response.statusCode();
	}

	@Test
	void testAdminGetUsersOk() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		String csrfToken = getCsrfToken(client);

		// Login as admin
		HttpRequest loginRequest = HttpRequest.newBuilder(URI.create(BASE_URL + "/login"))
				.header("X-XSRF-TOKEN", csrfToken)
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString("username=admin&password=Admin@12345"))
				.build();
		client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

		// GET /api/admin/users
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/admin/users")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 200 : "Expected 200, got " + response.statusCode();
	}

	@Test
	void testAdminWhoamiOk() throws Exception {
		HttpClient client = createHttpClientWithCookies();
		String csrfToken = getCsrfToken(client);

		// Login as admin
		HttpRequest loginRequest = HttpRequest.newBuilder(URI.create(BASE_URL + "/login"))
				.header("X-XSRF-TOKEN", csrfToken)
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString("username=admin&password=Admin@12345"))
				.build();
		client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

		// GET /api/user/whoami
		HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + "/api/user/whoami")).GET().build();
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		assert response.statusCode() == 200 : "Expected 200, got " + response.statusCode();
		assert response.body().contains("\"username\":\"admin\"") : "Expected admin in response";
	}
}
