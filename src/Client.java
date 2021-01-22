import java.net.Socket;
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
/**
 * Acts as the superclass for the `FileClient` and `GroupClient` classes to
 * refactor away the `connect`, and `disconnect` methods and also creating
 * helper functions that may be needed by both (e.g. `isConnected`).
 * 
 * Note that the variables `sock`, `output`, and `input` are accessible to
 * both `FileClient` and `GroupClient` without being defined within those
 * files.
 */
public abstract class Client {
	// These data members are protected so that they are private, but still
	// accessible to subclasses (i.e. `FileClient` and `GroupClient`).
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected Cipher aes_cipher;
	protected RSAPublicKey server_pub_key_rsa;
	protected double next_seq_num_expected_out;
	protected double next_seq_num_expected_in;

	public Client(RSAPublicKey server_pub_key_rsa) {
		//java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		this.server_pub_key_rsa = server_pub_key_rsa;
	}

	

	/**
	 * Establishes a connection between the client and the server. This
	 * connection can be interacted with (after the connection is established)
	 * by using the `input` and `output` data members where `input` refers to
	 * information sent from the server and `output` refers to information
	 * sent to the server from the client.
	 *
	 * @param server The IP address (or alias, e.g. "localhost") where the
	 * server is hosted.
	 * @param port The port on the host where the server is listening.
	 * @return True if a connection was established, false otherwise.
	 */
	public boolean connect(final String server, final int port) {
		try {
			sock = new Socket(server, port);
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
			this.next_seq_num_expected_out = 0;
			this.next_seq_num_expected_in = 0;
			//gen DH pub and priv keypair
			KeyPair dh_kp = ExchangeFunctions.generate_single_dh_keypair();

			//make new env to send to server with our dh pub key
			double env_seq_num = getNextSeqNumOut();
			incNextSeqNumOut();
			Envelope env = new Envelope("DHEXCHANGE", env_seq_num);
			env.addObject(dh_kp.getPublic());
			env.genAndSetMac();
			//encrypt said env with server pub key
			SealedObject encrypted_env = ExchangeFunctions.encryptEnvUsingRSA(env, this.server_pub_key_rsa);
			output.writeObject(encrypted_env);

			//get server resp envelope (only unencrypted env)
			Envelope server_resp = (Envelope)input.readObject();
			try {
				if (server_resp.getSeqNum() != next_seq_num_expected_in++ || !server_resp.verifyMAC()) {
					System.out.println("T5 verification Failed, closing connection");
					System.out.println("num expected: "+(next_seq_num_expected_in-1));
					System.out.println("num received: "+server_resp.getSeqNum());
					sock.close();
					return false;
				}
			} catch (Exception ex) {
				sock.close();
				return false;
			}
			if(server_resp.getMessage().equals("OK")) {
				Key server_pub_key_dh = (Key)server_resp.getObjContents().get(0);
				byte[] shared_secret = ExchangeFunctions.generate_shared_key(dh_kp.getPrivate(), server_pub_key_dh);
				if(shared_secret == null) {
					return false;
				}
				Cipher cipher = ExchangeFunctions.get_aes_cipher(shared_secret);
				if(cipher == null) {
					return false;
				} else {
					this.aes_cipher = cipher;
				}
			} else {
				return false;
			}
		} catch(Exception e) {
			return false;
		}
		return true;
	}

	/**
	 * Checks if a connection with the server is still active.
	 *
	 * @return True if the connection is still active, false otherwise.
	 */
	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * Disconnects from the server.
	 */
	public void disconnect() {
		if (isConnected()) {
			try {
				double env_seq_num = getNextSeqNumOut();
				incNextSeqNumOut();
				Envelope message = new Envelope("DISCONNECT", env_seq_num);
				message.genAndSetMac();
				ExchangeFunctions.sendEncryptedMessage(output, aes_cipher, message);


				// prevent the client from trying to send and receive data
				// after the connection is closed
				sock = null;
				output = null;
				input = null;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
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
