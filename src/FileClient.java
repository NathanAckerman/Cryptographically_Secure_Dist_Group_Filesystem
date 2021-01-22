import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;

import javax.crypto.SealedObject;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Provides all of the client functionality regarding the file server. This
 * class is instantiated and called in order to connect and interact with a
 * file server.
 */
public class FileClient extends Client implements FileClientInterface {
	public FileClient(RSAPublicKey server_pub_key_rsa) {
		super(server_pub_key_rsa);
	}

	/**
	 * Deletes a file from the connected server. This function may throw an
	 * exception if a connection to the server is not already established.
	 *
	 * @param filename The name of the file (path included) to delete from the
	 * server.
	 * @param token The user's authentication token to send to the server
	 * along with the request to verify the authenticity of their actions.
	 * @return False if the file could not be deleted from the server for
	 * expected reasons (file not found, invalid path, etc.), true otherwise.
	 * One notable quirk, this method returns true if there is an
	 * `IOException` or `ClassNotFoundException`.
	 */
	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		} else {
			remotePath = filename;
		}
		double env_seq_num = getNextSeqNumOut();
		incNextSeqNumOut();
		Envelope env = new Envelope("DELETEF", env_seq_num); //Success
		env.addObject(remotePath);
		env.addObject(token);
		try {
			env.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, env);
			output.reset();
			env = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (env.getSeqNum() != next_seq_num_expected_in++ || !env.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return false;
			}
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			} else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
	}

	/**
	 * Downloads a file from the connected server. This function may throw an
	 * exception if a connection to the server is not already established.
	 *
	 * @param sourceFile The path on the server to the file that is being
	 * downloaded.
	 * @param destFile The path on the client's machine that the file should
	 * be saved to.
	 * @param token The user's authentication token to provide verification.
	 * @return False if the file could not be downloaded for expected reasons,
	 * true otherwise. This method will return true if it encounters a
	 * `ClassNotFoundException`.
	 */
	public boolean download(String sourceFile, String destFile, UserToken token, GroupKey key) {
		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {


			if (!file.exists()) {
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);

				double env_seq_num = getNextSeqNumOut();
				incNextSeqNumOut();
				Envelope env = new Envelope("DOWNLOADF", env_seq_num); //Success
				env.addObject(sourceFile);
				env.addObject(token);
				env.genAndSetMac();
				ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, env);
				output.reset();

				// User gets sharefile sent from fileserver so they can get version and group
				env = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);
				
				try {
					if (env.getSeqNum() != next_seq_num_expected_in++ || !env.verifyMAC()) {
						System.out.println("T5 verification Failed, closing connection");
						sock.close();
						return false;
					}
				} catch (Exception ex) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
				ShareFile sf = (ShareFile)env.getObjContents().get(0);

				// Hashes key necessary amount of times to get to correct version
				String group = sf.getGroup();
				int encrypted_version = sf.getVersion();
				int user_version = key.getVersion();

				// check if encrypted using old key
				GroupKey version_key;
				if ( user_version > encrypted_version ) {
					int version_diff = encrypted_version - 1;

					version_key = new GroupKey( key.getOldKey(), 1 );
					for ( int i = 0; i < version_diff; i++ ) {
						version_key = version_key.increment();
					}
				}
				else {
					int version_diff = encrypted_version - user_version;

					version_key = key;
					for ( int i = 0; i < version_diff; i++ ) {
						version_key = version_key.increment();
					}
				}

				env = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

				try {
					if (env.getSeqNum() != next_seq_num_expected_in++ || !env.verifyMAC()) {
						System.out.println("T5 verification Failed, closing connection");
						sock.close();
						return false;
					}
				} catch (Exception ex) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
				while (env.getMessage().compareTo("CHUNK")==0) {
					fos.write( GroupKeyFunctions.decrypt( (byte[])env.getObjContents().get(0), version_key.getKey() ), 0, (Integer)env.getObjContents().get(1));
					System.out.printf(".");
					env_seq_num = getNextSeqNumOut();
					incNextSeqNumOut();
					env = new Envelope("DOWNLOADF", env_seq_num); //Success
					env.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, env);
					output.reset();
					env = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);
					try {
						if (env.getSeqNum() != next_seq_num_expected_in++ || !env.verifyMAC()) {
							System.out.println("T5 verification Failed, closing connection");
							sock.close();
							return false;
						}
					} catch (Exception ex) {
						System.out.println("T5 verification Failed, closing connection");
						sock.close();
						return false;
					}
				}
				fos.close();

				if(env.getMessage().compareTo("EOF")==0) {
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env_seq_num = getNextSeqNumOut();
					incNextSeqNumOut();
					env = new Envelope("OK", env_seq_num); //Success
					env.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, env);
					output.reset();
				} else {
					System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
					file.delete();
					return false;
				}
			}

			else {
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}


		} catch (IOException e1) {

			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;


		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		} catch ( Exception e1 ) {
			e1.printStackTrace();
		}
		return true;
	}

	/**
	 * Lists the files on the connected server that the user has access to.
	 * This access is determined from the token passed to the server.
	 *
	 * @param token The authentication token from which to determine the files
	 * that the user has access to.
	 * @return A list object containing the paths to the files on the server
	 * that this user has access to or null if the user has access to no files
	 * or an error is encountered.
	 */
	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		try {
			Envelope message = null, e = null;
			//Tell the server to return the member list
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("LFILES", env_seq_num);
			message.addObject(token); //Add requester's token
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();

			e = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (e.getSeqNum() != next_seq_num_expected_in++ || !e.verifyMAC()) {
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
			if(e.getMessage().equals("OK")) {
				//This cast creates compiler warnings. Sorry.
				return (List<String>)e.getObjContents().get(0);
			}

			return null;

		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	/**
	 * Uploads a file to the connected server. This function may throw an
	 * exception if a connection to the server is not already established.
	 *
	 * @param sourceFile The path on the client's machine to the file that is
	 * being uploaded.
	 * @param destFile The path on the server that the file should be saved to.
	 * @param group The group to place the file in.
	 * @param token The user's authentication token.
	 * @return True if the file was successfully uploaded, false otherwise.
	 */
	public boolean upload(String sourceFile, String destFile, String group, UserToken token, GroupKey key) {

		if (destFile.charAt(0)!='/') {
			destFile = "/" + destFile;
		}

		try {
			// attempt to open file first bc if fail, never talk to server
			FileInputStream fis = new FileInputStream(sourceFile);

			Envelope message = null, env = null;
			//Tell the server to return the member list
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			message = new Envelope("UPLOADF", env_seq_num);
			message.addObject(destFile);
			message.addObject(group);
			message.addObject(token); //Add requester's token
			message.addObject(key.getVersion()); // add current version of key being used to encrypt
			message.genAndSetMac();
			ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
			output.reset();


			env = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

			try {
				if (env.getSeqNum() != next_seq_num_expected_in++ || !env.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
			} catch (Exception ex) {
				System.out.println("T5 verification Failed, closing connection");
				sock.close();
				return false;
			}
			//If server indicates success, return the member list
			if(env.getMessage().equals("READY")) {
				System.out.printf("Meta data upload successful\n");

			} else {

				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}



			do {
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo("READY")!=0) {
					System.out.printf("Server error: %s\n", env.getMessage());
					return false;
				}
				env_seq_num = getNextSeqNumOut();
				incNextSeqNumOut();
				message = new Envelope("CHUNK", env_seq_num);
				int n = fis.read(buf); //can throw an IOException
				if (n > 0) {
					System.out.printf(".");
				} else if (n < 0) {
					System.out.println("Read error");
					return false;
				}

				message.addObject( GroupKeyFunctions.encrypt( buf, key.getKey() ) );
				message.addObject(Integer.valueOf(n));
				message.genAndSetMac();

				ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
				output.reset();

				env = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);


				try {
					if (env.getSeqNum() != next_seq_num_expected_in++ || !env.verifyMAC()) {
						System.out.println("T5 verification Failed, closing connection");
						sock.close();
						return false;
					}
				} catch (Exception ex) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}

			} while (fis.available()>0);

			//If server indicates success, return the member list
			if(env.getMessage().compareTo("READY")==0) {

				env_seq_num = getNextSeqNumOut();
				incNextSeqNumOut();
				message = new Envelope("EOF", env_seq_num);
				message.genAndSetMac();
				ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);
				output.reset();


				env = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);

				try {
					if (env.getSeqNum() != next_seq_num_expected_in++ || !env.verifyMAC()) {
						System.out.println("T5 verification Failed, closing connection");
						sock.close();
						return false;
					}
				} catch (Exception ex) {
					System.out.println("T5 verification Failed, closing connection");
					sock.close();
					return false;
				}
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				} else {

					System.out.printf("\nUpload failed: %s\n", env.getMessage());
					return false;
				}

			} else {

				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}

		} catch(FileNotFoundException e) {
			System.err.println("Error: File `"+sourceFile+"` was not found.");
			return false;
		} catch(Exception e1) {
			System.err.println("Error: " + e1.getMessage());
			e1.printStackTrace(System.err);
			return false;
		}
		return true;
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
