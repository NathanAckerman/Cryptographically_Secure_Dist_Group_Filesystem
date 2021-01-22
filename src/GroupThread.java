/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.net.Socket;
import java.lang.Thread;
import java.util.ArrayList;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.security.Key;
import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyFactory;
import javax.crypto.SealedObject;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.NoSuchAlgorithmException;

public class GroupThread extends Thread {
	private final Socket socket;
	private GroupServer my_gs;

	public GroupThread(Socket _socket, GroupServer _gs) {
		socket = _socket;
		my_gs = _gs;
	}

	public void run() {
		boolean proceed = true;
		Cipher aes_cipher = null;
		double next_seq_num_expected_out = 0;
		double next_seq_num_expected_in = 0;
		try {
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			//process the exchange object containing the dh public key for the client

			SealedObject exchange_obj = null;
			try {
				exchange_obj = (SealedObject)input.readObject();
			} catch(Exception ex) {
				Envelope response;
				response = new Envelope("FAIL", next_seq_num_expected_out++); //Server does not understand client request
				response.genAndSetMac();
				output.writeObject(response);
				output.reset();
				return;
			}
			//decrypt the initial envelope which should be encrypted with the gs pub key
			Envelope exchange_env = ExchangeFunctions.decryptEnvUsingRSA(exchange_obj, (RSAPrivateKey) my_gs.getPrivateKey());
			//if we failed to decrypt then this should reject
			if(exchange_env == null) {
				Envelope response;
				response = new Envelope("FAIL", next_seq_num_expected_out++); //Server does not understand client request
				response.genAndSetMac();
				output.writeObject(response);
				output.reset();
				return;
			} else {
				try {
					if (exchange_env.getSeqNum() != next_seq_num_expected_in++ || !exchange_env.verifyMAC()) {
						System.out.println("T5 verification Failed, closing connection");
						socket.close();
						return;
					}
				} catch (Exception ex) {
					socket.close();
					return;
				}
				//make sure it is valid
				if(exchange_env.getMessage().equals("DHEXCHANGE")){
					System.out.println("Request received: " + exchange_env.getMessage());
					Key client_dh_pub = (Key)exchange_env.getObjContents().get(0);
					Envelope response;
					response = new Envelope("OK", next_seq_num_expected_out++); //Server does not understand client request
					//make our dh keypair
					KeyPair dh_kp = ExchangeFunctions.generate_single_dh_keypair();
					//send out the public key
					response.addObject(dh_kp.getPublic());	
					
					byte[] shared_secret = ExchangeFunctions.generate_shared_key(dh_kp.getPrivate(), client_dh_pub);
					if(shared_secret == null) {
						response = new Envelope("FAIL", next_seq_num_expected_out++); //Server does not understand client request
						response.genAndSetMac();
						output.writeObject(response);
						output.reset();
						return;
					}

					//get the cipher that all socket communicatio should use after this message
					Cipher cipher = ExchangeFunctions.get_aes_cipher(shared_secret);
					if(cipher == null) {
						response = new Envelope("FAIL", next_seq_num_expected_out++); //Server does not understand client request
						response.genAndSetMac();
						output.writeObject(response);
						output.reset();
						return;
					} else {
						aes_cipher = cipher;
					}

					response.genAndSetMac();
					output.writeObject(response);
					output.reset();
				} else {
					Envelope response;
					response = new Envelope("FAIL", next_seq_num_expected_out++); //Server does not understand client request
					response.genAndSetMac();
					output.writeObject(response);
					output.reset();
					return;
				}
			}

			do {
				SealedObject sealed_obj = (SealedObject)input.readObject();
				Envelope message = ExchangeFunctions.decryptEnvelopeUsingAES(sealed_obj, aes_cipher);
				if(message == null) {
					System.out.println("AES ciphered message from client is not proper");
					return;
				}
				try {
					if (message.getSeqNum() != next_seq_num_expected_in++ || !message.verifyMAC()) {
						System.out.println("T5 verification Failed, closing connection");
						socket.close();
						return;
					}
				} catch (Exception ex) {
					socket.close();
					return;
				}
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				if(message.getMessage().equals("GET")) { //Client wants a token
					String username = (String)message.getObjContents().get(0); //Get the username
					String password = (String)message.getObjContents().get(1); //Get the password
					if(username == null || !validPassword( username, password )) {
						response = new Envelope("FAIL", next_seq_num_expected_out++);
						response.addObject(null);
						response.genAndSetMac();
						ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
					} else {
						UserToken yourToken = createToken(username); //Create a token

						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK", next_seq_num_expected_out++);
						response.addObject(yourToken);
						response.genAndSetMac();
						ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
					}
				} else if ( message.getMessage().equals( "GETKC" ) ) {

					if ( message.getObjContents().size() < 1 ) {
						response = new Envelope( "FAIL" , next_seq_num_expected_out++);
					} else {

						response = new Envelope( "FAIL" , next_seq_num_expected_out++);

						if ( message.getObjContents().get(0) != null ) {
							UserToken token = (UserToken) message.getObjContents().get(0);

							String username = token.getSubject();
							KeyChain keys = my_gs.userList.getKeyChain( username );

							response = new Envelope( "OK" , next_seq_num_expected_out-1);
							response.addObject( keys );
						}	

					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				} else if(message.getMessage().equals("CUSER")) { //Client wants to create a user
					if(message.getObjContents().size() < 2) {
						response = new Envelope("FAIL", next_seq_num_expected_out++);
					} else {
						response = new Envelope("FAIL", next_seq_num_expected_out++);

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								if(message.getObjContents().get(2) != null) {
									String username = (String)message.getObjContents().get(0); //Extract the username
									String password = (String)message.getObjContents().get(1); //Extract the password
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token

									if(createUser(username, password, yourToken)) {
										response = new Envelope("OK", next_seq_num_expected_out-1); //Success
									}
								} 
							}
						}
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				} else if(message.getMessage().equals("SRECP")) { //Client wants to designate recipient
					if(message.getObjContents().size() < 2) { // should be token & hash of pubkey
						response = new Envelope("FAIL", next_seq_num_expected_out++);
					} else {
						response = new Envelope("FAIL", next_seq_num_expected_out++);

						if(message.getObjContents().get(0) != null
						&& message.getObjContents().get(1) != null) {
							UserToken token = (Token)message.getObjContents().get(0);
							byte[] hpub = (byte[])message.getObjContents().get(1);

							// check that the token is still valid, and add recipient if so
							if(token.isExpired()) {
								response = new Envelope("FAIL-EXPIRED", next_seq_num_expected_out++);
							} else if(my_gs.validateSignature(token)) {
								// sign the hash and add recipient to the token
								token.setRecipient(my_gs.signBytes(hpub));
								// re-sign the token
								MessageDigest h = MessageDigest.getInstance("SHA-256");
								h.update(token.toSignatureString().getBytes());
								token.setSignature(my_gs.signBytes(h.digest()));
								// send it back
								response = new Envelope("OK", next_seq_num_expected_out-1);
								response.addObject(token);
								response.genAndSetMac();
								ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, 
									response);
							}
						}
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				} else if(message.getMessage().equals("DUSER")) { //Client wants to delete a user

					if(message.getObjContents().size() < 2) {
						response = new Envelope("FAIL", next_seq_num_expected_out++);
					} else {
						response = new Envelope("FAIL", next_seq_num_expected_out++);

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(deleteUser(username, yourToken)) {
									response = new Envelope("OK", next_seq_num_expected_out-1); //Success
								}
							}
						}
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				} else if(message.getMessage().equals("CGROUP")) { //Client wants to create a group

					if(message.getObjContents().size() < 2) {
						response = new Envelope("FAIL", next_seq_num_expected_out++);
					} else {
						response = new Envelope("FAIL", next_seq_num_expected_out++);

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								String groupName = (String)message.getObjContents().get(0); //Extract groupName
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								String userName = yourToken.getSubject(); // get userName who token was issued to

								// contain whether group and user currently exist
								boolean groupExists = my_gs.groupList.checkGroup( groupName );
								boolean userExists = my_gs.userList.checkUser( userName );

								// Makes sure group doesn't already exist and user does exist
								if( !groupExists && userExists ) {

									response = new Envelope("OK", next_seq_num_expected_out-1);

									createGroup( groupName, userName );

								}
							}
						}
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				} else if(message.getMessage().equals("DGROUP")) { //Client wants to delete a group
					
					if(message.getObjContents().size() < 2) {
						response = new Envelope("FAIL", next_seq_num_expected_out++);
					} else {
						response = new Envelope("FAIL", next_seq_num_expected_out++);

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								String groupName = (String)message.getObjContents().get(0); //Extract groupName
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								String userName = yourToken.getSubject(); // get userName who token was issued to

								// Determine if group exists and user exist
								boolean groupExists = my_gs.groupList.checkGroup( groupName );
								boolean userExists = my_gs.userList.checkUser( userName );

								if( groupExists && userExists ) { // make sure both group and user exist

									if ( my_gs.userList.getUserOwnership( userName ).contains( groupName ) ) { // make sure user is owner of group

										response = new Envelope("OK", next_seq_num_expected_out-1);

										deleteGroup( groupName, yourToken );

									}

								}
							}
						}
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				} else if(message.getMessage().equals("LMEMBERS")) { //Client wants a list of members in a group
					if(message.getObjContents().size() < 2) {
						response = new Envelope("FAIL", next_seq_num_expected_out++);
					} else {
						response = new Envelope("FAIL", next_seq_num_expected_out++);

						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								String groupName = (String)message.getObjContents().get(0); //Extract groupName
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								ArrayList<String> members = listMembers(groupName, yourToken);
								if(members != null) {
									response = new Envelope("OK", next_seq_num_expected_out-1);
									response.addObject(members);
								}
							}
						}
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				} else if(message.getMessage().equals("AUSERTOGROUP")) { //Client wants to add user to a group
					try {
						UserList ul = my_gs.userList;
						GroupList gl = my_gs.groupList;
						String username = (String)message.getObjContents().get(0);
						boolean user_exists = ul.checkUser(username);//make sure user exists
						if(user_exists) {
							//make sure the person doing this is the owner of a group
							String group_name = (String)message.getObjContents().get(1);
							UserToken the_token = (UserToken)message.getObjContents().get(2);
							ArrayList<String> token_ownerships = ul.getUserOwnership(the_token.getSubject());
							//fail if not the owner of the group
							if(!token_ownerships.contains(group_name)) {
								response = new Envelope("FAIL", next_seq_num_expected_out++);
							} else {
								boolean user_in_group = ul.getUserGroups(username).contains(group_name);
								if(user_in_group) {//fail if user is already in that group
									response = new Envelope("FAIL", next_seq_num_expected_out++);
								} else {
									ul.addGroup(username, group_name);
									gl.addMember(group_name, username);
									ul.putKey( username, group_name, gl.getKey( group_name ) );
									response = new Envelope("OK", next_seq_num_expected_out++);
								}
							}
						} else {//fail if user to add does not exist
							response = new Envelope("Fail", next_seq_num_expected_out++);
						}
					} catch(Exception e) {//this will fail if the message didnt have enough objects in it
						response = new Envelope("Fail", next_seq_num_expected_out++);
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);

				} else if(message.getMessage().equals("RUSERFROMGROUP")) { //Client wants to remove user from a group
					try {
						UserList ul = my_gs.userList;
						GroupList gl = my_gs.groupList;
						//make sure user to remove exists
						String username = (String)message.getObjContents().get(0);
						boolean user_exists = ul.checkUser(username);
						if(user_exists) {//if the user to remove does exist
							//make sure the token is from the group owner
							String group_name = (String)message.getObjContents().get(1);
							UserToken the_token = (UserToken)message.getObjContents().get(2);
							ArrayList<String> token_ownerships = ul.getUserOwnership(the_token.getSubject());
							//if not the group owner fail
							if(!token_ownerships.contains(group_name)) {
								response = new Envelope("FAIL", next_seq_num_expected_out++);
							} else {
								boolean user_in_group = ul.getUserGroups(username).contains(group_name);
								if(!user_in_group) {//fail if the user was not in that group
									response = new Envelope("FAIL", next_seq_num_expected_out++);
								} else {
									ul.removeGroup(username, group_name);
									gl.removeMember(group_name, username);
									// Now we need to redistribute keys
									ArrayList<String> curr_users = gl.getGroupUsers( group_name );
									for ( String user : curr_users ) {
										ul.putKey( user, group_name, gl.getKey( group_name ) );
									}
									response = new Envelope("OK", next_seq_num_expected_out++);
								}
							}
						} else {
							response = new Envelope("Fail", next_seq_num_expected_out++);
						}
					} catch(Exception e) {//this will fail if the message didnt have enough objects in it
						response = new Envelope("Fail", next_seq_num_expected_out++);
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);

				} else if(message.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				} else {
					response = new Envelope("FAIL", next_seq_num_expected_out++); //Server does not understand client request
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				}
			} while(proceed);
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	//Method to create tokens
	private UserToken createToken(String username) {
		//Check that user exists
		if(my_gs.userList.checkUser(username)) {
			try {
				// Issue a new token with server's name, user's name, and user's groups
				UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
				// Sign the token
				// hash the string to prevent it from getting too long
				MessageDigest h = MessageDigest.getInstance("SHA-256");
				h.update(yourToken.toSignatureString().getBytes());
				byte[] signature = my_gs.signBytes(h.digest());
				yourToken.setSignature(signature);
				return yourToken;
			} catch(NoSuchAlgorithmException e) {
				System.out.println("Missing SHA-256 algorithm.");
				e.printStackTrace();
				return null;
			}
		} else {
			return null;
		}
	}

	//Method to create a user
	private boolean createUser(String username, String password, UserToken yourToken) {
		String requester = yourToken.getSubject();

		//Check if requester exists
		if(my_gs.userList.checkUser(requester)) {
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN")) {
				//Does user already exist?
				if(my_gs.userList.checkUser(username)) {
					return false; //User already exists
				} else {
					my_gs.userList.addUser(username);
					my_gs.passwordList.addEntry(username, password, my_gs.userList.getSalt(username));
					return true;
				}
			} else {
				return false; //requester not an administrator
			}
		} else {
			return false; //requester does not exist
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken) {
		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester)) {
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN")) {
				//Does user exist?
				if(my_gs.userList.checkUser(username)) {
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++) {
						String curr_group = deleteFromGroups.get( index );
						my_gs.groupList.removeMember(username, curr_group);
						ArrayList<String> curr_users = my_gs.groupList.getGroupUsers( curr_group );
						for ( String user : curr_users ) {
							my_gs.userList.putKey( user, curr_group, my_gs.groupList.getKey( curr_group ) );
						}
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++) {
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					my_gs.passwordList.deleteEntry(username);

					return true;
				} else {
					return false; //User does not exist

				}
			} else {
				return false; //requester is not an administer
			}
		} else {
			return false; //requester does not exist
		}
	}

	// Method to list users contained within a group
	private ArrayList<String> listMembers(String groupname, UserToken yourToken) {
		String requester = yourToken.getSubject();

		// does group exist? is user in group? is user in/owner of admins?
		if(my_gs.groupList.checkGroup(groupname) &&
			(my_gs.groupList.getGroupUsers(groupname).contains(requester) ||
			my_gs.groupList.getGroupUsers("ADMIN").contains(requester))) {
			// return list of users in the group
			return my_gs.groupList.getGroupUsers(groupname);
		} else {
			return null;
		}
	}

	private void createGroup( String groupName, String userName ) {

		// create group within groupList
		my_gs.groupList.addGroup( groupName ); 

		// Add user as owner and member of group
		my_gs.groupList.addOwner( groupName, userName ); 
		my_gs.groupList.addMember( groupName, userName );

		// Add group to user data in userList
		my_gs.userList.addOwnership( userName, groupName );
		my_gs.userList.addGroup( userName, groupName );

		my_gs.userList.putKey( userName, groupName, my_gs.groupList.getKey( groupName ) );

	}

	private void deleteGroup( String groupName, UserToken t ) {

		// get lists of all Users and Owners of group
		ArrayList<String> allUsers = my_gs.groupList.getGroupUsers( groupName );
		ArrayList<String> allOwners = my_gs.groupList.getGroupOwners( groupName );

		// iterate through lists, removing group and ownership from all users
		for ( String tempUser : allUsers ) { my_gs.userList.removeGroup( tempUser, groupName ); }
		for ( String tempOwner : allOwners ) { my_gs.userList.removeOwnership( tempOwner, groupName ); }

		// delete group from list, garbage collector will take care of group data
		my_gs.groupList.deleteGroup( groupName );

	}

	private boolean validPassword(String username, String password) {
		return my_gs.passwordList.checkEntry(username, password, my_gs.userList.getSalt(username));
	}

}
