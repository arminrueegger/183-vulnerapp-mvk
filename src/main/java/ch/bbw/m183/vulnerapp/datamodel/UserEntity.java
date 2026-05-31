package ch.bbw.m183.vulnerapp.datamodel;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
@Entity
@Table(name = "users")
public class UserEntity {

	@Id
	@NotBlank
	@Size(min = 3, max = 50)
	@Pattern(regexp = "[a-zA-Z0-9_]+")
	String username;

	@Column
	@NotBlank
	@Size(max = 100)
	String fullname;

	@Column
	@NotBlank
	@Size(min = 8, max = 100)
	@Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).+$", message = "must contain a letter and a digit")
	String password;

	@Column
	@NotBlank
	@Pattern(regexp = "USER|ADMIN")
	String role;
}
