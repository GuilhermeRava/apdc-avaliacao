package com.util;

import java.util.UUID;

import org.apache.commons.codec.digest.DigestUtils;

import com.api.User;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;

public class AuthToken {
	public static final long EXPIRATION_TIME = 1000*60*60*2; //2h
	public String username;
	public String userRole;
	
	public String tokenID;
	public long creationData;
	public long expirationData;
	
	public AuthToken() {}
	
	public AuthToken(String username, String userRole) {
		this.username = username;
		this.tokenID = UUID.randomUUID().toString();
		this.creationData = System.currentTimeMillis();
		this.expirationData = this.creationData + AuthToken.EXPIRATION_TIME;
		this.userRole = userRole;
	}
	
	public AuthToken(String username, String userRole, String tokenID, Long creationData, Long expirationData) {
		this.username = username;
		this.tokenID = tokenID;
		this.creationData = creationData;
		this.expirationData = expirationData;
		this.userRole = userRole;
	}
	
	public Entity convertToDatastorageFormat(Key tokenKey) {
		return Entity.newBuilder(tokenKey)
				.set("username", this.username)
				.set("userRole", this.userRole)
				.set("tokenID", this.tokenID)
				
				.set("creation_time", this.creationData)
				.set("expiration_time", this.expirationData)
				
				.build();
	}
	
	public static AuthToken convertFromDatastorageFormat(Entity token) {
		return new AuthToken(
					token.getString("username"),
					token.getString("userRole"),
					token.getString("tokenID"),
					token.getLong("creation_time"),
					token.getLong("expiration_time")
				);
	}
}