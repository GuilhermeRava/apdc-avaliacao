package com.api;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;

/**
 * Represents a user in the system.
 */
public class User {
	
	public final static boolean isValidRole(String role) {
		boolean isValid = false;
		for(int i = 0; i < POSSIBLE_ROLES.length; i++) {
			String arrRole = POSSIBLE_ROLES[i];
			if(arrRole.equalsIgnoreCase(role)) {
				isValid = true;
				break;
			}
		}
		return isValid;
	}
	
	public final static String POSSIBLE_ROLES[] = new String[] 
		{
			"USER", // (utilizador final - default ou front-end) power: 0
			"GBO", // (utilizador de gestão BackOffice) power: 1
			"GA", // (utilizador Backend de gestão da aplicação) power: 2
			"SU", // (super-utilizador avançado com todos os poderes) power: 3
		};
	
	public final static int rolePower(String role) {
		int power = 0;
		for(int i = 0; i < POSSIBLE_ROLES.length; i++) {
			String arrRole = POSSIBLE_ROLES[i];
			if(arrRole.equals(role)) {
				break;
			}
			power++;
		}
		return power;
	}
	
	public final static boolean isValidState(String state) {
		boolean isValid = false;
		for(int i = 0; i < POSSIBLE_STATES.length; i++) {
			String arrState = POSSIBLE_STATES[i];
			if(arrState.equalsIgnoreCase(state)) {
				isValid = true;
				break;
			}
		}
		return isValid;
	}

	private final static String POSSIBLE_STATES[] = new String[] 
		{
			"ENABLED",
			"DISABLED"
		};
	
	public final static boolean isValidProfile(String profile) {
		boolean isValid = false;
		for(int i = 0; i < POSSIBLE_PROFILES.length; i++) {
			String arrProfile = POSSIBLE_PROFILES[i];
			if(arrProfile.equalsIgnoreCase(profile)) {
				isValid = true;
				break;
			}
		}
		return isValid;
	}
	
	private final static String POSSIBLE_PROFILES[] = new String[] 
			{
				"PUBLIC",
				"PRIVATE"
			};
	
	private String username;
	private String password;
	private String email;
	private String profile;
	private String houseNumber;
	private String cellphoneNumber;
	private String address;
	private String complementaryAddress;
	private String location;
	
	private String state;

	private String role;
	
	public User() {}

	public User(
			String username, 
			String password, 
			String email, 
			String houseNumber,
			String cellphoneNumber,
			String address,
			String complementaryAddress,
			String location
			) {
		this.setUsername(username); // format ()
		this.setPassword(password); // format ()
		this.setEmail(email); // format ()

		// optional data...
		this.setProfile(profile); // format ("Público" OR "Privado")
		this.setHouseNumber(houseNumber != null ? houseNumber : ""); // format (+351 NNNNNNNNN)
		this.setCellphoneNumber(cellphoneNumber != null ? cellphoneNumber : ""); // format (+351 91NNNNNNN ou 93NNNNNNN ou 96NNNNNNN)
		this.setAddress(address != null ? address : ""); // format ("Rua dos alunos de APDC20-21, 100, Piso 20")
		this.setComplementaryAddress(complementaryAddress != null ? complementaryAddress : ""); // format ("APDC Project Innovation Center for Fresh Ideas")
		this.setLocation(location != null ? location : "");

		// default new user account role is "USER", CHANGABLE LATER...
		this.setRole(POSSIBLE_ROLES[0]);

		// default new user account state is "ENABLED"
		this.setState(POSSIBLE_STATES[0]);
		
		// default new user account profile is "PUBLIC"
		this.setProfile(POSSIBLE_PROFILES[0]);
	}
	
	
	// used only in the method to convert from entity to User
	public User(
			String username, 
			String password, 
			String email, 
			String houseNumber,
			String cellphoneNumber,
			String address,
			String complementaryAddress,
			String profile,
			String role,
			String state
			) {
		this.setUsername(username); // format ()
		this.setPassword(password); // format ()
		this.setEmail(email); // format ()

		// optional data...
		this.setProfile(profile); // format ("Público" OR "Privado")
		this.setHouseNumber(houseNumber); // format (+351 NNNNNNNNN)
		this.setCellphoneNumber(cellphoneNumber); // format (+351 91NNNNNNN ou 93NNNNNNN ou 96NNNNNNN)
		this.setAddress(address); // format ("Rua dos alunos de APDC20-21, 100, Piso 20")
		this.setComplementaryAddress(complementaryAddress); // format ("APDC Project Innovation Center for Fresh Ideas")

		this.setRole(role);
		this.setState(state);	
		this.setProfile(profile);
	}
	
	public static boolean validateUsername(String username) {
		return username.trim() != "" && username.length() >= 3;
	}
	
	public static boolean validatePassword(String password) {
		return password.trim() != "" && password.length() >= 6;
	}
	
	public static boolean validUser(String username, String password, String passwordConfirm, String email) {
			boolean isValidUsernameSize = User.validateUsername(username);
			boolean isValidPasswordSize = User.validatePassword(password);
			
			boolean isValidPasswordConfirmation = password.equals(passwordConfirm);

			boolean isValidEmail = email.matches(".{3,}@.{3,}\\..{2,}");
			
			return isValidUsernameSize && isValidPasswordSize && isValidEmail && isValidPasswordConfirmation;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getCellphoneNumber() {
		return cellphoneNumber;
	}

	public void setCellphoneNumber(String cellphoneNumber) {
		this.cellphoneNumber = cellphoneNumber;
	}

	public String getComplementaryAddress() {
		return complementaryAddress;
	}

	public void setComplementaryAddress(String complementaryAddress) {
		this.complementaryAddress = complementaryAddress;
	}
	
	public String getLocation() {
		return this.location;
	}
	
	public void setLocation(String location) {
		this.location = location;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getHouseNumber() {
		return houseNumber;
	}

	public void setHouseNumber(String houseNumber) {
		this.houseNumber = houseNumber;
	}

	public String getProfile() {
		return profile;
	}

	public void setProfile(String profile) {
		this.profile = profile;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}
	
	public Entity convertToDatastorageFormat(Key userKey) {
		return Entity.newBuilder(userKey)
				.set("username", this.username)
				.set("password", DigestUtils.sha512Hex(this.password))
				.set("email", this.email)
				
				.set("houseNumber", this.houseNumber)
				.set("cellphoneNumber", this.cellphoneNumber)
				.set("complementaryAddress", this.complementaryAddress)
				.set("address", this.address)
				
				.set("profile", this.profile)
				.set("role", this.role)
				.set("state", this.state)
				
				.set("creation_time", Timestamp.now())
				
				.build();
	}
	
	public static User convertFromDatastorageFormat(Entity user) {
		return new User(
					user.getString("username"),
					user.getString("password"),
					user.getString("email"),
					user.getString("houseNumber"),
					user.getString("cellphoneNumber"),
					user.getString("address"),
					user.getString("complementaryAddress"),
					user.getString("profile"),
					user.getString("role"),
					user.getString("state")
				);
	}
}
