/* Implements the GroupClient Interface */

import java.util.List;
import java.io.IOException;
import java.util.ArrayList;
import java.io.ObjectInputStream;

import java.security.Key;
import java.math.BigInteger;
import java.security.KeyFactory;
import javax.crypto.SealedObject;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.NoSuchAlgorithmException;

public class GroupClient extends Client implements GroupClientInterface {

	public GroupClient(RSAPublicKey server_pub_key_rsa) {
		super(server_pub_key_rsa);
	}

	public UserToken getToken(String username, String password) {
		try {
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("GET", env_seq_num);
			message.addObject(username); //Add user name string
			message.addObject(password); //Add user password string
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			//Get the response from the server
			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("num expected: "+(next_seq_num_expected_in-1));
					System.out.println("num received: "+response.getSeqNum());
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return null;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return null;
			}

			//Successful response
			if(response.getMessage().equals("OK")) {
				//If there is a token in the Envelope, return it
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if(temp.size() == 1) {
					token = (UserToken)temp.get(0);
					return token;
				}
			}

			return null;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}

	}

	public KeyChain getKeyChain( UserToken token ) {

		try {

			Envelope message = null, response = null;

			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope( "GETKC" , env_seq_num);
			message.addObject( token );
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);
			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					System.out.println("num expected: "+(next_seq_num_expected_in-1));
					System.out.println("num received: "+response.getSeqNum());
					System.out.println(response.verifyMAC());
					sock.close();
					return null;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return null;
			}
			if ( response.getMessage().equals( "OK" ) ) {
				return (KeyChain) response.getObjContents().get(0);
			}

			return null;

		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public UserToken setRecipient(UserToken token, Key pubKey) {
		try {
			// define envelopes
			Envelope message = null, response = null;

			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			// from the key, create the hash that will be passed to the server
			MessageDigest h = MessageDigest.getInstance("SHA-256");
			h.update(pubKey.getEncoded());
			byte[] hashedKey = h.digest();

			// Tell the server to return the updated token
			message = new Envelope("SRECP", env_seq_num);
			message.addObject(token);
			message.addObject(hashedKey);

			// send the envelope
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			// get server's response
			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(),
				aes_cipher);

			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return null;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return null;
			}
			if(response.getMessage().equals("OK")) {
				// pull out the token and return it
				return (UserToken)response.getObjContents().get(0);
			} else {
				return null;
			}
		} catch(NoSuchAlgorithmException e) {
			System.err.println("Hashing algorithm: SHA-256 doesn't exist.");
			e.printStackTrace();
			return null;
		} catch(IOException e) {
			System.out.println("Unable to read in an object from file stream.");
			e.printStackTrace();
			return null;
		} catch(ClassNotFoundException e) {
			System.out.println("Unable to read SealedObject from file stream.");
			e.printStackTrace();
			return null;
		}
	}

	public boolean createUser(String username, String password, UserToken token) {
		try {
			Envelope message = null, response = null;
			//Tell the server to create a user
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("CUSER", env_seq_num);
			message.addObject(username); //Add user name string
			message.addObject(password); //Add user password string
			message.addObject(token); //Add the requester's token
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return false;
			}
			//If server indicates success, return true
			if(response.getMessage().equals("OK")) {
				return true;
			}

			return false;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUser(String username, UserToken token) {
		try {
			Envelope message = null, response = null;

			//Tell the server to delete a user
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("DUSER", env_seq_num);
			message.addObject(username); //Add user name
			message.addObject(token);  //Add requester's token
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return false;
			}

			//If server indicates success, return true
			if(response.getMessage().equals("OK")) {
				return true;
			}

			return false;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean createGroup(String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			//Tell the server to create a group
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("CGROUP", env_seq_num);
			message.addObject(groupname); //Add the group name string
			message.addObject(token); //Add the requester's token
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			
			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return false;
			}

			//If server indicates success, return true
			if(response.getMessage().equals("OK")) {
				return true;
			}

			return false;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteGroup(String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			//Tell the server to delete a group
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("DGROUP", env_seq_num);
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			
			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return false;
			}
			//If server indicates success, return true
			if(response.getMessage().equals("OK")) {
				return true;
			}

			return false;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token) {
		try {
			Envelope message = null, response = null;
			//Tell the server to return the member list
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("LMEMBERS", env_seq_num);
			message.addObject(group); //Add group name string
			message.addObject(token); //Add requester's token
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return null;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return null;
			}

			//If server indicates success, return the member list
			if(response.getMessage().equals("OK")) {
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			}

			return null;

		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean addUserToGroup(String username, String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			//Tell the server to add a user to the group
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("AUSERTOGROUP", env_seq_num);
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return false;
			}
			//If server indicates success, return true
			if(response.getMessage().equals("OK")) {
				return true;
			}

			return false;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			//Tell the server to remove a user from the group
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("RUSERFROMGROUP", env_seq_num);
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			response = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (response.getSeqNum() != next_seq_num_expected_in++ || !response.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return false;
			}
			//If server indicates success, return true
			if(response.getMessage().equals("OK")) {
				return true;
			}

			return false;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	private void incNextSeqNumOut() {
		this.next_seq_num_expected_out++;
	}

	private double getNextSeqNumOut() {
		return this.next_seq_num_expected_out;
	}

	private double getAndIncNextSeqNumOIn() {
		return next_seq_num_expected_in++;
	}
}
