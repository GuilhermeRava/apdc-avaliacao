package com.util;

public class UserAttributesData {
	public String profile;
	public String houseNumber;
	public String cellphoneNumber;
	public String address;
	public String complementaryAddress;
	public String location;

	public UserAttributesData() {};

	public UserAttributesData(
		String profile,
		String houseNumber,
		String cellphoneNumber,
		String address,
		String complementaryAddress,
		String location
	) {
		this.profile = profile;
		this.houseNumber = houseNumber;
		this.cellphoneNumber = cellphoneNumber;
		this.address = address;
		this.complementaryAddress = complementaryAddress;
		this.location = location;
	}
}
