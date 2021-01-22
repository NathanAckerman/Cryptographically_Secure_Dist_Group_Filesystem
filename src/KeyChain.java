// KeyChain.java
// Keeps track of user's keys

import java.io.*;
import java.util.*;

public class KeyChain implements java.io.Serializable {

	private static final long serialVersionUID = 13513954393543024L;

	// Maps group names to current key
	private Hashtable<String, GroupKey> keys = new Hashtable<String, GroupKey>();

	public GroupKey get( String groupname ) {
		return keys.get( groupname );
	}

	public void put( String groupname, GroupKey key ) {
		keys.put( groupname, key );
	}

}