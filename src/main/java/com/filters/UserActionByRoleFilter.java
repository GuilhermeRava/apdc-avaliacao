package com.filters;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.lang.reflect.Method;


import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;

import com.google.appengine.api.datastore.AdminDatastoreService.EntityBuilder;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.Transaction;
import com.google.cloud.datastore.StructuredQuery.CompositeFilter;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.gson.Gson;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.Provider;

import com.resources.UserResource;
import com.util.AuthToken;
import com.util.DataStorage;

@Provider
public class UserActionByRoleFilter implements ContainerRequestFilter {
	private final DataStorage ds = new DataStorage();
	
	@Context
	private ResourceInfo resourceInfo;

	private static final Logger LOG = Logger.getLogger(UserResource.class.getName());


	private final Gson g = new Gson();

	public UserActionByRoleFilter() {}

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {

		Method method = resourceInfo.getResourceMethod();
		
		// if method permit all, return sooner so we pass control to the method faster
		if(method.isAnnotationPresent(PermitAll.class)) {
			return;
		}
		
		List<String> token = requestContext.getHeaders().get("Token");
		if( token == null || token.isEmpty()) {
			requestContext.abortWith(Response.status(Response.Status.FORBIDDEN)
					.entity("Invalid token for this operation, please, log in.")
					.build());
			return;
		}

		// fix json string if it has double quotes...
		String fixedQuotesTokenJson = token.get(0).replaceAll("^\"|\"$", "");
		AuthToken authToken = g.fromJson(fixedQuotesTokenJson, AuthToken.class);
		
		// validate and get the real token in the data storage...
		Key userKey = ds.getDatastore().newKeyFactory().setKind("User").newKey(authToken.username);
		Key tokenKey = ds.getDatastore().newKeyFactory().setKind("Token").newKey(authToken.tokenID);
		
		// Entity tokenFromDB  = ds.getDatastore().get(tokenKey);
		
		Query<Entity> query = Query.newEntityQueryBuilder() 
				.setKind("Token")
				.setFilter(
						CompositeFilter.and(
			        PropertyFilter.hasAncestor(userKey),
			        PropertyFilter.eq("tokenID", authToken.tokenID))
			    )
				.build();

		QueryResults<Entity> usersByRole = ds.getDatastore().run(query);
		
		Entity tokenFromDB = null;
		try {
			tokenFromDB = usersByRole.next();	
		}
		catch(Exception e) {
			requestContext.abortWith(Response.status(Response.Status.FORBIDDEN)
					.entity("Invalid token.")
					.build());
			return;
		}
		
		if(tokenFromDB == null) {
			requestContext.abortWith(Response.status(Response.Status.FORBIDDEN)
					.entity("Invalid token.")
					.build());
			return;
		}
		
		String userRole = tokenFromDB.getString("userRole");
		
		Timestamp created = Timestamp.ofTimeMicroseconds(tokenFromDB.getLong("creation_time"));
		Timestamp expiration = Timestamp.ofTimeMicroseconds(tokenFromDB.getLong("expiration_time"));
		
		// expired token...
		if(created.compareTo(expiration) > 0) {
			requestContext.abortWith(Response.status(Response.Status.FORBIDDEN)
					.entity("Expired token, please, log in again.")
					.build());
			
			// remove token from db
			Transaction txn = ds.getDatastore().newTransaction();
			try {
				txn.delete(tokenKey);
				txn.commit();
			}
			catch(DatastoreException dse) {
				txn.rollback();
				LOG.severe("failed to remove token from db: " + dse);
			}
			finally {
				if(txn.isActive()) {
					txn.rollback();
				}
			}
			return;
		}
		
		// TODO: secret validation key only the server knows, maybe hash username + email ???
		
		// if token is valid, store in a context so the method can access it
		requestContext.setProperty("usertoken", AuthToken.convertFromDatastorageFormat(tokenFromDB));

		LOG.fine("User requested path: " + /*path*/ "-" + " with token: " + authToken.tokenID);
		//Verify user access
        if(method.isAnnotationPresent(RolesAllowed.class)) {
            RolesAllowed rolesAnnotation = method.getAnnotation(RolesAllowed.class);
            Set<String> rolesSet = new HashSet<String>(Arrays.asList(rolesAnnotation.value()));
              
            // is user role valid?
            if(!rolesSet.contains(userRole)) {
            	requestContext.abortWith(Response.status(Response.Status.FORBIDDEN)
    					.entity("Invalid user role for this operation.")
    					.build());
    			return;
            }
        }
	}
}