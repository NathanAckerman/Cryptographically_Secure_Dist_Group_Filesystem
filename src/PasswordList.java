/* This list stores user passwords */

import java.util.*;

import org.bouncycastle.crypto.generators.BCrypt;

public class PasswordList implements java.io.Serializable {

	private static final long serialVersionUID = 1752478376709132924L;
	private Hashtable<String, byte[]> list = new Hashtable<String, byte[]>(); // Password list
	private final int cost = 8;

	public synchronized void addEntry(String username, String password, byte[] salt) {
		list.put(username, hash(password, salt));
	}

	public synchronized boolean checkEntry(String username, String password, byte[] salt) {
		return Arrays.equals(list.get(username), hash(password, salt));
	}

	public synchronized void deleteEntry(String username) {
		list.remove(username);
	}

	private byte[] hash(String s, byte[] salt) {
		return BCrypt.generate(s.getBytes(), salt, cost);
	}

}
