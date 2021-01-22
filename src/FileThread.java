/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

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

public class FileThread extends Thread {
	private final Socket socket;
	private FileServer my_fs;

	public FileThread(Socket _socket, FileServer _fs) {
		socket = _socket;
		my_fs = _fs;
	}

	public void run() {
		boolean proceed = true;
		Cipher aes_cipher = null;
		double next_seq_num_expected_out = 0;
		double next_seq_num_expected_in = 0;
		try {
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;
			
			SealedObject exchange_obj = null;
			try {
				exchange_obj = (SealedObject)input.readObject();
			} catch(Exception ex) {
				response = new Envelope("FAIL", next_seq_num_expected_out++); //Server does not understand client request
				response.genAndSetMac();
				output.writeObject(response);
				output.reset();
				return;
			}
			//decrypt the initial envelope which should be encrypted with the gs pub key
			Envelope exchange_env = ExchangeFunctions.decryptEnvUsingRSA(exchange_obj, (RSAPrivateKey)my_fs.getPrivateKey());
			//if we failed to decrypt then this should reject
			if(exchange_env == null) {
				response = new Envelope("FAIL", next_seq_num_expected_out++); //Server does not understand client request
				response.genAndSetMac();
				output.writeObject(response);
				output.reset();
				return;
			} else {
				//make sure it is valid
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
				if(exchange_env.getMessage().equals("DHEXCHANGE")){
					Key client_dh_pub = (Key)exchange_env.getObjContents().get(0);
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
					response = new Envelope("FAIL", next_seq_num_expected_out++); //Server does not understand client request
					response.genAndSetMac();
					output.writeObject(response);
					output.reset();
					return;
				}
			}

			do {

				SealedObject sealed_obj = (SealedObject)input.readObject();
				Envelope e = ExchangeFunctions.decryptEnvelopeUsingAES(sealed_obj, aes_cipher);
				if(e == null) {
					System.out.println("AES ciphered message from client is not proper");
					return;
				}

				try {
					if (e.getSeqNum() != next_seq_num_expected_in++ || !e.verifyMAC()) {
						System.out.println("T5 verification Failed, closing connection");
						socket.close();
						return;
					}
				} catch (Exception ex) {
					socket.close();
					return;
				}
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES")) {
					List<String> list_of_matches = new ArrayList<String>();
					UserToken user_token = (UserToken)e.getObjContents().get(0);
					// validate token
					if(user_token.isExpired()) {
						response = new Envelope("FAIL-EXPIRED", next_seq_num_expected_out++);
					} else if(my_fs.validateSignature(user_token)) {
						List<String> list_of_user_groups = user_token.getGroups();
						FileList file_list = FileServer.fileList;
						for(ShareFile share_file : file_list.getFiles()) {
							if(list_of_user_groups.contains(share_file.getGroup())) {
								list_of_matches.add(share_file.getPath());
							}
						}
						response = new Envelope("OK", next_seq_num_expected_out++);
						response.addObject(list_of_matches);
					} else {
						response = new Envelope("FAIL-UNAUTHORIZED", next_seq_num_expected_out++);
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				} else if(e.getMessage().equals("UPLOADF")) {

					if(e.getObjContents().size() < 3) {
						response = new Envelope("FAIL-BADCONTENTS", next_seq_num_expected_out++);
					} else {
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH", next_seq_num_expected_out++);
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP", next_seq_num_expected_out-1);
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN", next_seq_num_expected_out-1);
						} 
						if(e.getObjContents().get(3) == null) {
							response = new Envelope("FAIL-BADKEY", next_seq_num_expected_out-1);
						}else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
							int version = ( (Integer) e.getObjContents().get(3) ).intValue(); // Extract key version

							if(yourToken.isExpired()) {
								response = new Envelope("FAIL-EXPIRED", next_seq_num_expected_out++);
							} else if(my_fs.validateSignature(yourToken)) {
								if (FileServer.fileList.checkFile(remotePath)) {
									System.out.printf("Error: file already exists at %s\n", remotePath);
									response = new Envelope("FAIL-FILEEXISTS", next_seq_num_expected_out++); //Success
								} else if (!yourToken.getGroups().contains(group)) {
									System.out.printf("Error: user missing valid token for group %s\n", group);
									response = new Envelope("FAIL-UNAUTHORIZED", next_seq_num_expected_out++); //Success
								} else  {
									FileOutputStream fos = new FileOutputStream("shared_files/"+remotePath.replace('/', '_'));
									System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

									response = new Envelope("READY", next_seq_num_expected_out++); //Success
									response.genAndSetMac();
									ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);

									e = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);
									try {
										if (e.getSeqNum() != next_seq_num_expected_in++ || !e.verifyMAC()) {
											System.out.println("T5 verification Failed, closing connection");
											socket.close();
											return;
										}
									} catch (Exception ex) {
										socket.close();
										return;
									}
									while (e.getMessage().compareTo("CHUNK")==0) {
										fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
										response = new Envelope("READY", next_seq_num_expected_out++); //Success
										response.genAndSetMac();
										ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
										e = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);
										try {
											if (e.getSeqNum() != next_seq_num_expected_in++ || !e.verifyMAC()) {
												System.out.println("T5 verification Failed, closing connection");
												socket.close();
												return;
											}
										} catch (Exception ex) {
											socket.close();
											return;
										}
									}

									if(e.getMessage().compareTo("EOF")==0) {
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, version);
										response = new Envelope("OK", next_seq_num_expected_out++); //Success
									} else {
										System.out.printf("Error reading file %s from client\n", remotePath);
										response = new Envelope("ERROR-TRANSFER", next_seq_num_expected_out++);
										// remove created file
									}
									fos.close();
								}
							} else {
								response = new Envelope("FAIL-UNAUTHORIZED", next_seq_num_expected_out++);
							}
						}
					}
					response.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, response);
				} else if (e.getMessage().compareTo("DOWNLOADF")==0) {
					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					int version = my_fs.fileList.getVersion( "/" + remotePath );

					if(t.isExpired()) {
						response = new Envelope("FAIL-EXPIRED", next_seq_num_expected_out++);
					} else if(my_fs.validateSignature(t)) {
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_FILEMISSING", next_seq_num_expected_out++);
							e.genAndSetMac();
							ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, e);
						} else if (!t.getGroups().contains(sf.getGroup())) {
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION", next_seq_num_expected_out++);
							e.genAndSetMac();
							ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, e);
						} else {
							try {
								File f = new File("shared_files/_"+remotePath.replace('/', '_'));
								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_NOTONDISK", next_seq_num_expected_out++);
									e.genAndSetMac();
									ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, e);
								} else {

									// Send the user the sharefile so they can get group and version
									Envelope e_sharefile = new Envelope( "SHAREFILE" , next_seq_num_expected_out++);
									e_sharefile.addObject( sf );
									e_sharefile.genAndSetMac();
									ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, e_sharefile);

									FileInputStream fis = new FileInputStream(f);

									do {
										byte[] buf = new byte[4096];
										if (e.getMessage().compareTo("DOWNLOADF")!=0) {
											System.out.printf("Server error: %s\n", e.getMessage());
											break;
										}
										e = new Envelope("CHUNK", next_seq_num_expected_out++);
										int n = fis.read(buf); //can throw an IOException
										if (n > 0) {
											System.out.printf(".");
										} else if (n < 0) {
											System.out.println("Read error");

										}

										e.addObject(buf);
										e.addObject(Integer.valueOf(n));
										e.genAndSetMac();
										ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, e);

										e = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);
										try {
											if (e.getSeqNum() != next_seq_num_expected_in++ || !e.verifyMAC()) {
												System.out.println("T5 verification Failed, closing connection");
												socket.close();
												return;
											}
										} catch (Exception ex) {
											socket.close();
											return;
										}
									} while (fis.available()>0);

									//If server indicates success, return the member list
									if(e.getMessage().compareTo("DOWNLOADF")==0) {
										e = new Envelope("EOF", next_seq_num_expected_out++);
										e.genAndSetMac();
										ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, e);

										e = ExchangeFunctions.decryptEnvelopeUsingAES((SealedObject)input.readObject(), aes_cipher);
										try {
											if (e.getSeqNum() != next_seq_num_expected_in++ || !e.verifyMAC()) {
												System.out.println("T5 verification Failed, closing connection");
												socket.close();
												return;
											}
										} catch (Exception ex) {
											socket.close();
											return;
										}
										if(e.getMessage().compareTo("OK")==0) {
											System.out.printf("File data upload successful\n");
										} else {
											System.out.printf("Upload failed: %s\n", e.getMessage());
										}
									} else {
										System.out.printf("Upload failed: %s\n", e.getMessage());
									}

									fis.close();
								}
							} catch(Exception e1) {
								System.err.println("Error: " + e.getMessage());
								e1.printStackTrace(System.err);
							}
						}
					} else {
						response = new Envelope("FAIL-UNAUTHORIZED", next_seq_num_expected_out++);
					}
				} else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					if(t.isExpired()) {
						response = new Envelope("FAIL-EXPIRED", next_seq_num_expected_out++);
					} else if(my_fs.validateSignature(t)) {
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_DOESNTEXIST", next_seq_num_expected_out++);
						} else if (!t.getGroups().contains(sf.getGroup())) {
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION", next_seq_num_expected_out++);
						} else {

							try {


								File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_FILEMISSING", next_seq_num_expected_out++);
								} else if (f.delete()) {
									System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
									FileServer.fileList.removeFile("/"+remotePath);
									e = new Envelope("OK", next_seq_num_expected_out++);
								} else {
									System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_DELETE", next_seq_num_expected_out++);
								}


							} catch(Exception e1) {
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
								e = new Envelope(e1.getMessage(), next_seq_num_expected_out++);
							}
						}
					} else {
						response = new Envelope("FAIL-UNAUTHORIZED", next_seq_num_expected_out++);
					}
					e.genAndSetMac();
					ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, e);
				} else if(e.getMessage().equals("DISCONNECT")) {
					socket.close();
					proceed = false;
				}
			} while(proceed);
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

}
