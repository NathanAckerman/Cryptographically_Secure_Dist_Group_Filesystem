// GroupKey.java
// GroupKey object

public class GroupKey implements java.io.Serializable {

	private static final long serialVersionUID = -85427592402349235L;

	private int version;
	private byte[] oldKey;
	private byte[] key;

	public GroupKey() throws Exception {
		this( GroupKeyFunctions.getSharedSecret() );
	}

	public GroupKey( byte[] _key ) throws Exception {
		this( _key, 0 );
	}

	public GroupKey( byte[] _key, int _version ) throws Exception {
		this( _key, _version, null );
	}

	public GroupKey( byte[] _key, int _version, byte[] _oldKey ) throws Exception {
		key = _key;
		version = _version;
		oldKey = _oldKey;
	}

	public byte[] getOldKey() {
		return oldKey;
	}

	public void setOldKey( byte[] _oldKey ) {
		oldKey = _oldKey;
	}

	public byte[] getKey() {
		return key;
	}

	public int getVersion() {
		return version;
	}

	public void update( byte[] _key, int _version ) {
		key = _key;
		version = _version;
	}

	public GroupKey increment() throws Exception {
		return new GroupKey( GroupKeyFunctions.hash( key ), version + 1 );
	}	

}