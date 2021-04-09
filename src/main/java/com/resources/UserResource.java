package com.resources;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;

import com.api.User;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.PathElement;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.Transaction;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.gson.Gson;
import com.util.AuthToken;
import com.util.ChangePasswordData;
import com.util.DataStorage;
import com.util.LoginData;
import com.util.RegisterData;
import com.util.UserAttributesData;

@Path("/user") 
@Produces(MediaType.APPLICATION_JSON+ ";charset=utf-8" )
public class UserResource {

	private static final Logger LOG = Logger.getLogger(UserResource.class.getName());

	private final Gson g = new Gson();

	private final DataStorage ds = new DataStorage();

	public UserResource () {}

	@PermitAll
	@POST
	@Path("/") 
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doRegister(RegisterData data) {
		LOG.fine("Register attempt by user: " + data.username);
		LOG.fine("json: " + g.toJson(data).toString());

		boolean isValidUser = User.validUser(
				data.username, 
				data.password,
				data.passwordConfirm,
				data.email
				);

		if( !isValidUser) {
			LOG.severe("Invalid user data..., username or password is invalid");
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Invalid user data")).build();
		}

		Key userKey = ds.getDatastore().newKeyFactory().setKind("User").newKey(data.username);
		Transaction txn = ds.getDatastore().newTransaction();
		try {
			Entity existingUser = txn.get(userKey);

			if(existingUser != null) {
				LOG.severe("USER EXISTS! " + existingUser.toString());
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("User already exists")).build();
			}
			else {
				User user = new User(
						data.username, 
						data.password,
						data.email,
						data.houseNumber,
						data.cellphoneNumber,
						data.address,
						data.complementaryAddress,
						data.location
						);

				Entity userToStore = user.convertToDatastorageFormat(userKey);

				System.out.println("converted entity: " + userToStore.toString());

				LOG.info("BEFORE USER PUT!!");
				txn.put(userToStore);
				txn.commit();
				LOG.info("USER ADDED!! " + userToStore.toString());
				return Response.status(Status.OK).entity(g.toJson(user)).build();
			}

		}
		catch(DatastoreException dse) {
			txn.rollback();
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Register user, to store in datastorage: " + dse)).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
			}
		}
	}

	@PermitAll
	@POST
	@Path("/{username}/login") 
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doUserLogin(
			@Context HttpServletRequest servletRequest, 
			@PathParam("username") String username, 
			LoginData data) {
		boolean isValidUsername = User.validateUsername(username);
		boolean isValidPassword = User.validatePassword(data.password);

		if(!isValidUsername || !isValidPassword) {
			LOG.severe("invalid username or password for user: " + username + " pass: " + data.password);
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Bad login data: " + data.password)).build();
		}

		Key userKey = ds.getDatastore().newKeyFactory().setKind("User").newKey(username);

		Entity existingUser = ds.getDatastore().get(userKey);

		if(existingUser == null) {
			LOG.severe("USER DOESNT EXISTS!");
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("User doesnt exists")).build();
		}

		if(!existingUser.getString("password").equals(DigestUtils.sha512Hex(data.password))) {
			LOG.severe("BD PASS: " + existingUser.getString("password"));
			LOG.severe("received hashed PASS: " + DigestUtils.sha512Hex(data.password));
			LOG.severe("WRONG PASSWORD FOR USER: " + username + " password: " + data.password);
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Wrong password")).build();
		}

		AuthToken token = new AuthToken(username, existingUser.getString("role"));

		Key tokenKey = ds.getDatastore().newKeyFactory()
				.addAncestors(PathElement.of("User",username))
				.setKind("Token")
				.newKey(token.tokenID);
		Transaction txn = ds.getDatastore().newTransaction();
		try {
			txn.put(token.convertToDatastorageFormat(tokenKey));
			txn.commit();
			return Response.ok().entity(g.toJson(token)).build();
		}
		catch(DatastoreException dse) {
			txn.rollback();
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to store token in datastorage: " + dse)).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
			}
		}
	}

	@RolesAllowed({"USER", "GBO", "GA", "SU"})
	@POST
	@Path("/{username}/logout") 
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doUserLogout(
			@Context HttpServletRequest servletRequest, 
			@Context HttpHeaders httpHeaders, 
			@PathParam("username") String userToLogout) {

		AuthToken receivedToken = (AuthToken) servletRequest.getAttribute("usertoken");

		boolean isValidUsername = User.validateUsername(userToLogout);

		if(!isValidUsername) {
			LOG.severe("invalid username or token for user: " + userToLogout + " token: " + receivedToken.tokenID);
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Bad logout data: " + receivedToken.tokenID)).build();
		}

		Key tokenKey = ds.getDatastore().newKeyFactory()
			.addAncestors(PathElement.of("User",userToLogout))
			.setKind("Token")
			.newKey(receivedToken.tokenID);
		Entity tokenInDB = ds.getDatastore().get(tokenKey);

		if(
			tokenInDB == null  
			|| !tokenInDB.getString("tokenID").equals(receivedToken.tokenID) 
			|| !tokenInDB.getString("username").equals(userToLogout)
			) {
			LOG.severe("not same user: " + userToLogout + " token user: " + receivedToken.username);
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("not right user for token: " + userToLogout)).build();
		}

		Transaction txn = ds.getDatastore().newTransaction();
		try {
			txn.delete(tokenKey);
			txn.commit();
			return Response.ok().entity(g.toJson("log out with success! removed token from DB")).build();
		}
		catch(DatastoreException dse) {
			txn.rollback();
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to delete token from datastorage: " + dse)).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
			}
		}
	}

	@RolesAllowed({"USER", "GBO", "GA", "SU"})
	@DELETE
	@Path("/{username}")
	public Response doDelete(
			@Context HttpServletRequest servletRequest, 
			@Context HttpHeaders httpHeaders, 
			@PathParam("username") String userToDelete ) {
		LOG.fine("doDelete for user: " + userToDelete);

		AuthToken authToken = (AuthToken) servletRequest.getAttribute("usertoken");

		LOG.fine("with token: " + authToken.tokenID + " requesting user: " + authToken.username);

		// a user can delete himself, the role doesnt matter
		Key userKey = ds.getDatastore().newKeyFactory().setKind("User").newKey(userToDelete);

		if(userToDelete.equals(authToken.username)) {
			LOG.fine("(equal user) userToDelete: " + userToDelete + " requesting user: " + authToken.username);
			Transaction txn = ds.getDatastore().newTransaction();
			try {
				txn.delete(userKey);
				txn.commit();
				return Response.ok().entity(g.toJson("deleted user: " + userToDelete)).build();
			}
			catch(DatastoreException dse) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to delete user:" + userToDelete)).build();
			}
			finally {
				if(txn.isActive()) {
					txn.rollback();
				}
			}
		}
		else {
			LOG.fine("(not equal user) userToDelete: " + userToDelete + " requesting user: " + authToken.username);
			// check roles "power" if a different user is requesting the deletion,  
			// not possible ( GBO cant delete GA for example )
			int requesterRolePower = User.rolePower(authToken.userRole);

			Entity userFromDB = ds.getDatastore().get(userKey);

			if(userFromDB == null) {
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to delete user:" + userToDelete)).build();
			}

			// now we need to get the user object to measure power levels... if they are equal or greater allow the deletion
			int userToDeleteRolePower = User.rolePower(userFromDB.getString("role"));

			if(requesterRolePower < userToDeleteRolePower) {
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to delete user:" + userToDelete)).build();
			}

			// we know that the power is equal or greater, so allow deletion...
			Transaction txn = ds.getDatastore().newTransaction();
			try {
				txn.delete(userKey);
				txn.commit();
				return Response.ok().entity(g.toJson("deleted user: " + userToDelete)).build();
			}
			catch(DatastoreException dse) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to delete user:" + userToDelete)).build();
			}
			finally {
				if(txn.isActive()) {
					txn.rollback();
				}
			}
		}
	}

	@RolesAllowed({"USER", "GBO", "GA", "SU"})
	@PUT
	@Path("/{username}")
	public Response doChangeUserAttributes(
			@Context HttpServletRequest servletRequest, 
			@Context HttpHeaders httpHeaders, 
			@PathParam("username") String userToChangeStats, 
			UserAttributesData data) {
		// if is own user, can change attributes, except ROLE AND STATUS.

		AuthToken authToken = (AuthToken) servletRequest.getAttribute("usertoken");

		LOG.fine("(PUT) Change stats attempt by user: " + authToken.username);

		String requestingUser = authToken.username;

		// if invalid received profile to change | can be "public" or "private" only
		if(!User.isValidProfile(data.profile)) {
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Invalid profile ( it needs to be 'public' or 'private' )")).build();
		}

		// only the own user can change his data
		if(!requestingUser.equals(userToChangeStats)) {
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("changing another user is not possible")).build();
		}

		Key userToChangeRoleKey = ds.getDatastore().newKeyFactory().setKind("User").newKey(userToChangeStats);		
		Transaction txn = ds.getDatastore().newTransaction();
		try {
			Entity userToChangeRoleDB = ds.getDatastore().get(userToChangeRoleKey);

			if(userToChangeRoleDB == null) {
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("User doesnt exist: " + userToChangeStats)).build();
			}
			User tempUser = User.convertFromDatastorageFormat(userToChangeRoleDB);

			tempUser.setAddress(data.address);
			tempUser.setComplementaryAddress(data.complementaryAddress);
			tempUser.setCellphoneNumber(data.cellphoneNumber);
			tempUser.setHouseNumber(data.houseNumber);
			tempUser.setProfile(data.profile);
			tempUser.setLocation(data.location);

			txn.put(tempUser.convertToDatastorageFormat(userToChangeRoleKey));
			txn.commit();

			return Response.ok().entity(g.toJson("Changed user stats")).build();
		}
		catch(DatastoreException dse) {
			txn.rollback();
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to change user stats: " + dse)).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
			}
		}
	}

	@PUT
	@RolesAllowed({"GA", "SU"})
	@Path("/{username}/role/{newRole}")
	public Response doChangeRole(
			@Context HttpServletRequest servletRequest,
			@Context HttpHeaders httpHeaders, 
			@PathParam("username") String userToChangeRole, 
			@PathParam("newRole") String newRole) {

		AuthToken authToken = (AuthToken) servletRequest.getAttribute("usertoken");

		LOG.fine("(PUT) Change role attempt by user: " + authToken.username);

		String requestingUser = authToken.username;
		
		if(!User.isValidRole(newRole)) {
		return Response.status(Status.BAD_REQUEST).entity(g.toJson("role to change doesnt exist: " + newRole)).build();
		}

		// here a user cant change the status of himself,
		// even a user SU, because a SU should stay SU.
		if(requestingUser.equals(userToChangeRole)) {
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Changing your own role is not possible")).build();
		}

		Key userToChangeRoleKey = ds.getDatastore().newKeyFactory().setKind("User").newKey(userToChangeRole);		
		Transaction txn = ds.getDatastore().newTransaction();
		try {	
			Entity userToChangeRoleDB = ds.getDatastore().get(userToChangeRoleKey);

			if(userToChangeRoleDB == null) {
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("User doesnt exist: " + userToChangeRole)).build();
			}

			int requesterRolePower = User.rolePower(authToken.userRole);
			int newRolePower = User.rolePower(newRole);

			if(
					(requesterRolePower <= newRolePower && !authToken.userRole.equals("SU"))
					|| !newRole.equals("SU")
					) {
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("insufficient privileges to change user role")).build();
			}

			String userToChangeRoleOldRole = userToChangeRoleDB.getString("role");

			User tempUser = User.convertFromDatastorageFormat(userToChangeRoleDB);

			// change old role
			tempUser.setRole(newRole.toUpperCase());

			txn.put(tempUser.convertToDatastorageFormat(userToChangeRoleKey));
			txn.commit();

			return Response.ok().entity(g.toJson("Changed user role from (" + userToChangeRoleOldRole + ") to " + newRole)).build();
		}
		catch(DatastoreException dse) {
			txn.rollback();
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to change user role: " + userToChangeRole)).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
			}
		}
	}

	@PUT
	@RolesAllowed({"GBO", "GA", "SU"})
	@Path("/{username}/state/{state}")
	public Response doChangeUserState(
			@Context HttpServletRequest servletRequest,
			@Context HttpHeaders httpHeaders, 
			@PathParam("username") String userToChangeState, 
			@PathParam("state") String stateToChangeTo) {

		AuthToken authToken = (AuthToken) servletRequest.getAttribute("usertoken");

		LOG.fine("(PUT) Change state attempt by user: " + authToken.username);

		String requestingUser = authToken.username;

		// here a user cant change the status of himself...
		// even a user SU, because if doesnt make sense to disable this account
		if(requestingUser.equals(userToChangeState)) {
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Changing your own state is not possible")).build();
		}

		// check if its a allowed received state ( for now, "ENABLED" and "DISABLED" )
		if(!User.isValidState(stateToChangeTo)) {
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("invalid state to change to: " + stateToChangeTo)).build();
		}

		Key userKey = ds.getDatastore().newKeyFactory().setKind("User").newKey(userToChangeState);
		Transaction txn = ds.getDatastore().newTransaction();
		try {
			Entity userFromDB = ds.getDatastore().get(userKey);

			if(userFromDB == null) {
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("User doesnt exist: " + userToChangeState)).build();
			}

			int requesterRolePower = User.rolePower(authToken.userRole);
			int userToDeleteRolePower = User.rolePower(userFromDB.getString("role"));

			// only a different user with a power + 1 can change the account status
			if(requesterRolePower <= userToDeleteRolePower) {
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("insufficient privileges to change user state: " + userToChangeState)).build();
			}

			// here we know that we can change the user state.
			String oldState = userFromDB.getString("state");

			User tempUser = User.convertFromDatastorageFormat(userFromDB);

			// change old state
			tempUser.setState(stateToChangeTo.toUpperCase());

			txn.put(tempUser.convertToDatastorageFormat(userKey));
			txn.commit();
			return Response.ok().entity(g.toJson("Changed user (" + userToChangeState + ") state from (" + oldState + ") to: " + stateToChangeTo.toUpperCase())).build();
		}
		catch(DatastoreException dse) {
			txn.rollback();
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to change user state: " + userToChangeState)).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
			}
		}
	}

	// OP8.1A,  
	// Dentro da sessao de LOGIN, mostrar os atributos do utilizador que estao registados na
	// conta do utilizador com perfil publico (todos os roles podem executar)
	@GET
	@RolesAllowed({"USER", "GBO", "GA", "SU"})
	@Path("/{username}/info")
	public Response doGetUserInfo(
			@Context HttpServletRequest servletRequest,
			@Context HttpHeaders httpHeaders, 
			@PathParam("username") String userToGetInfo) {

		LOG.fine("(GET) Get user info: " + userToGetInfo);

		Key userKey = ds.getDatastore().newKeyFactory().setKind("User").newKey( userToGetInfo);

		Entity userFromDB = ds.getDatastore().get(userKey);
		
		if(userFromDB == null) {
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("User doesnt exist: " + userToGetInfo)).build();
		}

		if(userFromDB.getString("profile").equalsIgnoreCase("private")) {
			return Response.ok().entity(g.toJson("User: " + userToGetInfo + " has a private profile.")).build();
		}

		User tempUser = User.convertFromDatastorageFormat(userFromDB);

		// remove password from the response, even if it is hashed
		tempUser.setPassword(null);

		return Response.ok().entity(g.toJson(tempUser)).build();
	}


	// OP8.2D
	// Mostrar todos os utilizadores dado um certo ROLE
	@GET
	@PermitAll
	@Path("/")
	public Response doGetUsersByRole(
			@Context HttpServletRequest servletRequest,
			@Context HttpHeaders httpHeaders,
			@QueryParam("role") String role) {

		LOG.fine("(GET) Get users username by role ");
		
		if(role == null || role.trim().equals("")) {
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("No role received. Pass one role in the query like so: '/rest/user/?role=user'")).build();
		}

		Query<Entity> query = Query.newEntityQueryBuilder()
				.setKind("User")
				.setFilter(PropertyFilter.eq("role", role.toUpperCase()))
				.build();

		QueryResults<Entity> usersByRole = ds.getDatastore().run(query);
		
		List<String> parsedUsersByRole = new ArrayList<String>();
		usersByRole.forEachRemaining( user -> {
			parsedUsersByRole.add(user.getString("username"));
		});

		return Response.ok().entity(g.toJson(parsedUsersByRole)).build();
	}
	
	// OP8.3A
	// OP8.1D - Mudanca de password do utilizador na sessao: exige o fornecimento da password
	// corrente e a nova password (que deve sempre ser confirmada duas vezes).
	@PUT
	@RolesAllowed({"USER", "GBO", "GA", "SU"})
	@Path("/{username}/change-password")
	public Response doChangeUserPassword(
			@Context HttpServletRequest servletRequest,
			@Context HttpHeaders httpHeaders, 
			@PathParam("username") String userToChangePass, 
			ChangePasswordData data) {
			
		AuthToken authToken = (AuthToken) servletRequest.getAttribute("usertoken");

		LOG.fine("(PUT) User is changing pass: " + userToChangePass);
		
		if(!authToken.username.equals(userToChangePass)) {
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Cant change another user password")).build();
		}
		
		if(!data.newPassword.equals(data.newPasswordConfirm)) {
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("new password doesnt match in both inputs.")).build();
		}
				
		Key userKey = ds.getDatastore().newKeyFactory().setKind("User").newKey(userToChangePass);
		Transaction txn = ds.getDatastore().newTransaction();
		try {
			Entity userFromDB = ds.getDatastore().get(userKey);

			User tempUser = User.convertFromDatastorageFormat(userFromDB);
			
			String oldPasswordFromUserDB = tempUser.getPassword();
			String hashedReceivedOldPassword = DigestUtils.sha512Hex(data.oldPassword);
			
			if(!hashedReceivedOldPassword.equals(oldPasswordFromUserDB)) {
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to Changed user password, old pass doesnt match.")).build();
			}
			
			// we can proceed to change the password
			String hashedNewPass = DigestUtils.sha512Hex(data.newPassword);

			tempUser.setPassword(hashedNewPass);

			txn.put(tempUser.convertToDatastorageFormat(userKey));
			txn.commit();
			return Response.ok().entity(g.toJson("Changed password with success")).build();
		}
		catch(DatastoreException dse) {
			txn.rollback();
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("failed to Changed user password " + dse)).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
			}
		}
	}
	
	// Util method used in a cron job to create the Super User
	@GET
	@PermitAll
	@Path("/utils/create-su")
	public Response doCreateSU() {
		Key userKey = ds.getDatastore().newKeyFactory().setKind("User").newKey("SUPERUSER");
		Transaction txn = ds.getDatastore().newTransaction();
		try {
			Entity existingUser = txn.get(userKey);

			if(existingUser != null) {
				LOG.severe("USER EXISTS! " + existingUser.toString());
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity(g.toJson("SU already exists")).build();
			}
			else {
				User user = new User(
						"SUPERUSER",
						"SUPERUSER",
						"SUPERUSER@EMAIL.COM",
						"",
						"",
						"",
						"",
						""
						);
				user.setRole("SU");
				
				Entity userToStore = user.convertToDatastorageFormat(userKey);

				System.out.println("converted entity: " + userToStore.toString());

				LOG.info("BEFORE USER PUT!!");
				txn.put(userToStore);
				txn.commit();
				LOG.info("USER ADDED!! " + userToStore.toString());
				return Response.status(Status.OK).entity(g.toJson(user)).build();
			}

		}
		catch(DatastoreException dse) {
			txn.rollback();
			return Response.status(Status.BAD_REQUEST).entity(g.toJson("Register user, to store in datastorage: " + dse)).build();
		}
		finally {
			if(txn.isActive()) {
				txn.rollback();
			}
		}
	}
}
