/*This list represents the groups on the server*/
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Enumeration;

public class GroupList implements java.io.Serializable {
	private static final long serialVersionUID = 1831112395914676095L;
	private Hashtable<String, Group> list = new Hashtable<>();

	public synchronized void addGroup(String groupname) {
		Group newGroup = new Group(groupname);
		list.put(groupname, newGroup);
	}
	
	public synchronized void deleteGroup(String groupname) {
		list.remove(groupname);
	}
	
	public synchronized boolean checkGroup(String groupname) {
		return list.containsKey(groupname);
	}

	public synchronized ArrayList<String> getGroupUsers(String groupname) {
		return list.get(groupname).getUsers();
	}

	public synchronized ArrayList<String> getGroupOwners(String groupname) {
		return list.get(groupname).getOwners();
	}

	public synchronized void addMember(String group, String username) {
		list.get(group).addUser(username);
	}

	public synchronized void removeMember(String group, String username) {
		list.get(group).removeUser(username);
	}

	public synchronized void addOwner(String group, String username) {
		list.get(group).addOwner(username);
	}

	public synchronized void removeOwner(String group, String username) {
		list.get(group).removeOwner(username);
	}

	public synchronized GroupKey getKey( String groupname ) {
		return list.get( groupname ).getKey();
	}

	public synchronized ArrayList<String> getAllGroups() {
		Enumeration enu = list.keys();
		ArrayList<String> groups = new ArrayList<>();
		while(enu.hasMoreElements()) {
			groups.add((String)enu.nextElement());
		}
		return groups;
	}


	class Group implements java.io.Serializable {
		private static final long serialVersionUID = -6988403106670866701L;
		private String name;
		private ArrayList<String> users;
		private ArrayList<String> owners;

		private GroupKey genesis_key;
		private GroupKey[] keys;
		private int curr_key;

		private final int MAX_KEYS = 100;

		public Group(String _name) {
			name = _name;
			users = new ArrayList<String>();
			owners = new ArrayList<String>();
			initKeys( null );
		}

		private void initKeys( byte[] oldKey ) {
			try {
				genesis_key = new GroupKey();
				keys = new GroupKey[MAX_KEYS];
				keys[0] = genesis_key;
				for ( int i = 1; i < MAX_KEYS; i++ ) {
					keys[i] = new GroupKey( GroupKeyFunctions.hash( keys[i - 1].getKey() ), i, oldKey );
				}
				curr_key = MAX_KEYS - 1;
			} catch ( Exception e ) {
				e.printStackTrace();
			}
			
		}

		private void decrementKey() {
			if ( curr_key == 1 ) {
				initKeys( getKey().getKey() );
			} else {
				curr_key--;
			}
		}

		public GroupKey getKey() {
			return keys[curr_key];
		}

		public ArrayList<String> getUsers() {
			return users;
		}

		public ArrayList<String> getOwners() {
			return owners;
		}

		public void addUser(String user) {
			if(user != null && !users.contains(user)) {
				users.add(user);
			}
		}

		public void removeUser(String user) {
			if(!owners.isEmpty() && owners.contains(user) && owners.size() == 1) {
				deleteGroup(this.name);
				return;
			}

			if(!users.isEmpty()) {
				if(users.contains(user)) {
					users.remove(users.indexOf(user));
					decrementKey();
				}
			}

		}

		public void addOwner(String user) {
			if(user != null) {
				owners.add(user);
			}
			if(!users.contains(user)) {
				users.add(user);
			}
		}

		public void removeOwner(String user) {
			if(!owners.isEmpty() && owners.contains(user)) {
				owners.remove(owners.indexOf(user));
			}
		}
	}
}
