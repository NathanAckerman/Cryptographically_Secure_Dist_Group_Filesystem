/* This list represents the users on the server */
import java.util.*;
import java.security.*;

public class UserList implements java.io.Serializable {

	/**
	 *
	 */
	private static final long serialVersionUID = 7600343803563417992L;
	private Hashtable<String, User> list = new Hashtable<String, User>();

	public synchronized byte[] getSalt(String username) {
		return list.get(username).getSalt();
	}

	public synchronized void addUser(String username) {
		User newUser = new User();
		list.put(username, newUser);
	}

	public synchronized void deleteUser(String username) {
		list.remove(username);
	}

	public synchronized boolean checkUser(String username) {
		if(list.containsKey(username)) {
			return true;
		} else {
			return false;
		}
	}

	public synchronized ArrayList<String> getUserGroups(String username) {
		return list.get(username).getGroups();
	}

	public synchronized ArrayList<String> getUserOwnership(String username) {
		return list.get(username).getOwnership();
	}

	public synchronized void addGroup(String user, String groupname) {
		list.get(user).addGroup(groupname);
	}

	public synchronized void removeGroup(String user, String groupname) {
		list.get(user).removeGroup(groupname);
	}

	public synchronized void addOwnership(String user, String groupname) {
		list.get(user).addOwnership(groupname);
	}

	public synchronized void removeOwnership(String user, String groupname) {
		list.get(user).removeOwnership(groupname);
	}

	public synchronized KeyChain getKeyChain( String username ) {
		return list.get( username ).getKeyChain();
	}

	public synchronized GroupKey getKey( String username, String groupname ) {
		return list.get( username ).getKey( groupname );
	}

	public synchronized void putKey( String username, String groupname, GroupKey key ) {
		list.get( username ).putKey( groupname, key );
	}

	public synchronized ArrayList<String> getAllUsers() {
		Enumeration enu = list.keys();
		ArrayList<String> users = new ArrayList<>();
		while(enu.hasMoreElements()) {
			users.add((String)enu.nextElement());
		}
		return users;
	}

	class User implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;

		private byte[] salt; // User's random salt

		private KeyChain keys;

		public User() {
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();

			salt = new byte[16];
			(new SecureRandom()).nextBytes(salt);

			keys = new KeyChain();
		}

		public KeyChain getKeyChain() {
			return keys;
		}

		public void putKey( String groupname, GroupKey key ) {
			keys.put( groupname, key ); 
		}

		public GroupKey getKey( String groupname ) {
			return keys.get( groupname );  
		}

		public byte[] getSalt() {
			return salt;
		}

		public ArrayList<String> getGroups() {
			return groups;
		}

		public ArrayList<String> getOwnership() {
			return ownership;
		}

		public void addGroup(String group) {
			groups.add(group);
		}

		public void removeGroup(String group) {
			if(!groups.isEmpty()) {
				if(groups.contains(group)) {
					groups.remove(groups.indexOf(group));
				}
			}
		}

		public void addOwnership(String group) {
			ownership.add(group);
		}

		public void removeOwnership(String group) {
			if(!ownership.isEmpty()) {
				if(ownership.contains(group)) {
					ownership.remove(ownership.indexOf(group));
				}
			}
		}

	}

}
