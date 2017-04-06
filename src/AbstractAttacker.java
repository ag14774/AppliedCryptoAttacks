import java.io.BufferedReader;
import java.io.PrintWriter;

public abstract class AbstractAttacker implements IAttacker {

	
	final private static char[] toHex = "0123456789ABCDEF".toCharArray();

	protected BufferedReader target_out = null;
	protected PrintWriter target_in = null;
	protected int interactions;
	
	protected byte[] recovered_bytes;
	
	public AbstractAttacker(BufferedReader target_out, PrintWriter target_in) {
		this.target_out = target_out;
		this.target_in = target_in;
		this.interactions = 0;
	}
	
	@Override
	public String getRecoveredMaterial() {
		String s = "";
		for(byte b : this.recovered_bytes){
			s += String.format("%02X", b);
		}
		return s;
	}

	@Override
	public int getInteractions() {
		return interactions;
	}

	@Override
	abstract public void attack();
	
	public String intArrayToHex(int[] m) { //int array but represents an array of bytes. I WANT UNSIGNED TYPES!!!!
		StringBuilder res = new StringBuilder();
		for(int i = 0; i < m.length; i++) {
			res.append(toHex[( m[i] >> 4 ) & 0x0F]);
			res.append(toHex[( m[i]      ) & 0x0F]);
		}
		return res.toString();
	}
	
	/*Byte array represented as int array*/
	public int[] hexToIntArray(String hex) {
		int[] res = new int[hex.length()/2];
		for(int i = 0; i < hex.length(); i += 2) {
			int left  = Character.digit(hex.charAt(i  ), 16) << 4;
			int right = Character.digit(hex.charAt(i+1), 16);
			res[i / 2] = (byte) 0xFF&(left + right);
		}
		return res;
	}
	
	public int[] byteArrayToIntArray(byte[] arr) {
		int[] res = new int[arr.length];
		for(int i = 0;i<arr.length; i++){
			res[i] = arr[i] & 0xFF;
		}
		return res;
	}
	
	public byte[] intToByteArray(int[] arr) {
		byte[] res = new byte[arr.length];
		for(int i = 0;i<arr.length; i++){
			res[i] = (byte) arr[i];
		}
		return res;
	}

}
