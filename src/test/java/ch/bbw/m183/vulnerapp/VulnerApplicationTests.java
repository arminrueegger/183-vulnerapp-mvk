package ch.bbw.m183.vulnerapp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VulnerApplicationTests {

	@LocalServerPort
	int port;

	WebTestClient client;

	@BeforeEach
	void setup() {
		client = WebTestClient.bindToServer()
				.baseUrl("http://localhost:" + port)
				.build();
	}

	record Session(String jsessionid, String xsrf) {}

	Session login(String username, String password) {
		EntityExchangeResult<byte[]> seed = client.get().uri("/api/blog")
				.exchange()
				.expectStatus().isOk()
				.expectBody().returnResult();
		String initialXsrf = lastCookieValue(seed, "XSRF-TOKEN");

		EntityExchangeResult<byte[]> loginRes = client.post().uri("/login")
				.cookie("XSRF-TOKEN", initialXsrf)
				.header("X-XSRF-TOKEN", initialXsrf)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.bodyValue("username=" + username + "&password=" + password)
				.exchange()
				.expectStatus().isOk()
				.expectBody().returnResult();

		String jsessionid = lastCookieValue(loginRes, "JSESSIONID");

		// fresh GET to pick up the rotated CSRF token (CsrfAuthenticationStrategy replaces it on login)
		EntityExchangeResult<byte[]> probe = client.get().uri("/api/user/whoami")
				.cookie("JSESSIONID", jsessionid)
				.exchange()
				.expectStatus().isOk()
				.expectBody().returnResult();
		String xsrf = lastCookieValue(probe, "XSRF-TOKEN");
		return new Session(jsessionid, xsrf);
	}

	static String lastCookieValue(EntityExchangeResult<?> result, String name) {
		var cookies = result.getResponseCookies().get(name);
		if (cookies == null || cookies.isEmpty()) {
			return "";
		}
		String last = "";
		for (var c : cookies) {
			if (!c.getValue().isEmpty()) {
				last = c.getValue();
			}
		}
		return last;
	}

	@Nested
	@DisplayName("anonymous")
	class Anonymous {

		@Test
		void rootIsPublic() {
			client.get().uri("/").exchange().expectStatus().isOk();
		}

		@Test
		void blogListIsPublic() {
			client.get().uri("/api/blog").exchange().expectStatus().isOk();
		}

		@Test
		void cannotPostBlog() {
			client.post().uri("/api/blog")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"t\",\"body\":\"b\"}")
					.exchange()
					.expectStatus().isUnauthorized();
		}

		@Test
		void cannotCallWhoami() {
			client.get().uri("/api/user/whoami").exchange().expectStatus().isUnauthorized();
		}

		@Test
		void cannotCallAdmin() {
			client.get().uri("/api/admin/users").exchange().expectStatus().isUnauthorized();
		}

		@Test
		void actuatorHealthHidesDetails() {
			client.get().uri("/actuator/health")
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.status").isEqualTo("UP")
					.jsonPath("$.components").doesNotExist();
		}
	}

	@Nested
	@DisplayName("user fuu")
	class UserAuth {

		Session session;

		@BeforeEach
		void loginAsUser() {
			session = login("fuu", "barbarbar1");
		}

		@Test
		void whoamiReturnsCurrentUser() {
			client.get().uri("/api/user/whoami")
					.cookie("JSESSIONID", session.jsessionid())
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.username").isEqualTo("fuu")
					.jsonPath("$.fullname").isEqualTo("Johanna Doe");
		}

		@Test
		void postBlogWithoutCsrfRejected() {
			client.post().uri("/api/blog")
					.cookie("JSESSIONID", session.jsessionid())
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"hi\",\"body\":\"there\"}")
					.exchange()
					.expectStatus().isForbidden();
		}

		@Test
		void postBlogWithCsrfWorks() {
			client.post().uri("/api/blog")
					.cookie("JSESSIONID", session.jsessionid())
					.cookie("XSRF-TOKEN", session.xsrf())
					.header("X-XSRF-TOKEN", session.xsrf())
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"hi\",\"body\":\"there\"}")
					.exchange()
					.expectStatus().isOk();
		}

		@Test
		void adminEndpointsForbidden() {
			client.get().uri("/api/admin/users")
					.cookie("JSESSIONID", session.jsessionid())
					.exchange()
					.expectStatus().isForbidden();
		}

		@Test
		void logoutSucceeds() {
			client.post().uri("/logout")
					.cookie("JSESSIONID", session.jsessionid())
					.cookie("XSRF-TOKEN", session.xsrf())
					.header("X-XSRF-TOKEN", session.xsrf())
					.exchange()
					.expectStatus().isNoContent();
		}
	}

	@Nested
	@DisplayName("admin")
	class AdminAuth {

		Session session;

		@BeforeEach
		void loginAsAdmin() {
			session = login("admin", "super5ecret");
		}

		@Test
		void canListUsers() {
			client.get().uri("/api/admin/users")
					.cookie("JSESSIONID", session.jsessionid())
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.content[?(@.username=='admin')]").exists();
		}

		@Test
		void canCreateAndDeleteUser() {
			client.post().uri("/api/admin/users")
					.cookie("JSESSIONID", session.jsessionid())
					.cookie("XSRF-TOKEN", session.xsrf())
					.header("X-XSRF-TOKEN", session.xsrf())
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"newbie\",\"fullname\":\"New Bee\",\"password\":\"swordfish9\",\"role\":\"USER\"}")
					.exchange()
					.expectStatus().isOk();

			client.delete().uri("/api/admin/users/newbie")
					.cookie("JSESSIONID", session.jsessionid())
					.cookie("XSRF-TOKEN", session.xsrf())
					.header("X-XSRF-TOKEN", session.xsrf())
					.exchange()
					.expectStatus().isOk();
		}

		@Test
		void healthWithDetailsForAdmin() {
			client.get().uri("/actuator/health")
					.cookie("JSESSIONID", session.jsessionid())
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.status").isEqualTo("UP")
					.jsonPath("$.components").exists();
		}
	}

	@Nested
	@DisplayName("validation")
	class Validation {

		@Test
		void emptyBlogTitleRejected() {
			Session s = login("fuu", "barbarbar1");
			client.post().uri("/api/blog")
					.cookie("JSESSIONID", s.jsessionid())
					.cookie("XSRF-TOKEN", s.xsrf())
					.header("X-XSRF-TOKEN", s.xsrf())
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"\",\"body\":\"there\"}")
					.exchange()
					.expectStatus().isBadRequest();
		}

		@Test
		void weakPasswordRejected() {
			Session s = login("admin", "super5ecret");
			client.post().uri("/api/admin/users")
					.cookie("JSESSIONID", s.jsessionid())
					.cookie("XSRF-TOKEN", s.xsrf())
					.header("X-XSRF-TOKEN", s.xsrf())
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"weak\",\"fullname\":\"W\",\"password\":\"abc\",\"role\":\"USER\"}")
					.exchange()
					.expectStatus().isBadRequest();
		}

		@Test
		void wrongPasswordRejected() {
			client.post().uri("/login")
					.contentType(MediaType.APPLICATION_FORM_URLENCODED)
					.bodyValue("username=fuu&password=nope")
					.exchange()
					.expectStatus().isUnauthorized();
		}
	}
}
