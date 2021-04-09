package com.util;

import java.util.logging.Logger;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Transaction;
import com.resources.UserResource;

public class DataStorage {
	private static final Logger LOG = Logger.getLogger(UserResource.class.getName());

	private final Datastore dataStore = DatastoreOptions.getDefaultInstance().getService();
	
	public Datastore getDatastore() {
		return this.dataStore;
	}
	
//	Alguns	padrões	para	a	criacao	de	chaves:	
////		Com	Kind	e	Key	dados	pelo	programador	
//	Key	k	=	datastore.newKeyFactory().setKind("Kind").newKey("Key");	
////		Com	Kind	mas	idenQficador	gerado	automaQcatemente
//	KeyFactory keyFactory	=	datastore.newKeyFactory().setKind("Kind");	
//	Key	k	=	datastore.allocateId(keyFactory.newKey());	
////		Com	Antecessores	
//	Key	k	=	datastore.newKeyFactory()	
//					.addAncestors(PathElement.of("Kind0",	"Key0"),	...,	PathElement.of("KindN",	"KeyN")	)	
//					.setKind("Kind")	
//					.newKey("Key");

//	public boolean doRegister(RegisterData data) {
//		boolean isUserCreated = false;
//		
//		if( !data.validRegistration()) {
//			LOG.severe("Invalid user data..., username or password is empty");
//			return isUserCreated;
//		}
//
//		Key userKey = dataStore.newKeyFactory().setKind("User").newKey(data.username);
//		Entity user = Entity.newBuilder(userKey)
//				.set("user_pwd", DigestUtils.sha512Hex(data.password))
//				.set("user_creation_time", Timestamp.now())
//				.build();
//		try {
//			dataStore.put(user);
//			isUserCreated = true;
//			LOG.fine("User created with key: " + data.username);
//		}
//		catch(Exception e) {
//			LOG.severe("failed to create user in google DB: " + data.username);
//			LOG.severe(e.toString());
//			
//		}
//		return isUserCreated;
//	}
//
//	public Response doRegisterV2(RegisterData data) {
//
//		if( !data.validRegistration()) {
//			return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parma").build();
//		}
//
//		Transaction txn = dataStore.newTransaction();
//		try {
//			Key userKey = dataStore.newKeyFactory().setKind("User").newKey(data.username);
//			Entity user = txn.get(userKey);
//
//			if(user != null) {
//				return Response.status(Status.BAD_REQUEST).entity("User exists").build();
//			}
//			else {
//				user = Entity.newBuilder(userKey)
//						.set("user_name", data.username)
//						.set("user_pwd", DigestUtils.sha512Hex(data.password))
//						.set("user_creation_time", Timestamp.now())
//						.build();
//
//				txn.put(user);
//				txn.commit();
//				return Response.ok("{}").build();
//			}
//
//		}
//		finally {
//			if(txn.isActive()) {
//				txn.rollback();
//			}
//		}
//
//	}
}
