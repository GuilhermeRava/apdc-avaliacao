package com.util;

public class RegisterData {
	public String username;
	public String password;
	public String passwordConfirm;
	public String email;
	public String profile;
	public String houseNumber;
	public String cellphoneNumber;
	public String address;
	public String complementaryAddress;
	public String location;

	public RegisterData() {}

	public RegisterData(
			String username, 
			String password, 
			String passwordConfirm, 
			String email, 
			String profile, 
			String houseNumber,
			String cellphoneNumber,
			String address,
			String complementaryAddress,
			String location
			) {
		this.username = username; // format ()
		this.password = password; // format ()
		this.passwordConfirm = passwordConfirm; // format ()
		this.email= email; // format ()

		// optional data...
		this.profile = profile; // format ("Público" OR "Privado")
		this.houseNumber = houseNumber; // format (+351 NNNNNNNNN)
		this.cellphoneNumber = cellphoneNumber; // format (+351 91NNNNNNN ou 93NNNNNNN ou 96NNNNNNN)
		this.address = address; // format ("Rua dos alunos de APDC20-21, 100, Piso 20")
		this.complementaryAddress = complementaryAddress; // format ("APDC Project Innovation Center for Fresh Ideas")~
		this.location= location; // format (código postal XXXX-XXX)
		
		// default new user account role is "USER", CHANGABLE LATER...
		// this.role = "USER";

		// default new user account state is "enabled"
		// this.STATE = "ENABLED";
	}
}
