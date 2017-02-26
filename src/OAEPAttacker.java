import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

public class OAEPAttacker implements IAttacker {
	
	/* Move these to AbstractAttacker */
	private BufferedReader target_out = null;
	private PrintWriter target_in = null;
	private int interactions;
	
	private BigInteger N;
	private BigInteger e;
	private byte[] label;
	private BigInteger ciphertext;
	
	private int k; //How many bytes
	private BigInteger B;
	
	private byte[] recovered_bytes;
	
	
	public OAEPAttacker(BufferedReader target_out, PrintWriter target_in,
						String N_hex, String e_hex, String label_hex,
						String ciphertext_hex) {
		/*First 3 lines to abstract class*/
		this.target_out = target_out;
		this.target_in = target_in;
		this.interactions = 0;
		
		this.N = new BigInteger(N_hex, 16);
		this.e = new BigInteger(e_hex, 16);
		if(label_hex.trim().equals("")) {
			this.label = null;
		}
		else {
			this.label = new byte[label_hex.length() / 2];
			for(int i = 0; i < label_hex.length(); i += 2) {
				int left  = Character.digit(label_hex.charAt(i  ), 16) << 4;
				int right = Character.digit(label_hex.charAt(i+1), 16);
				this.label[i / 2] = (byte) (left + right);
			}
		}
		this.ciphertext = new BigInteger(ciphertext_hex, 16);
		this.k = N_hex.length() / 2;  // Number of bytes
		this.B = BigInteger.ZERO.setBit(8*(k-1));
		
	}
	
	private int interact(final String label, final String ciphertext) {
		target_in.println(label);
		target_in.println(ciphertext);
		int r = 0;
		try {
			r = Integer.parseInt(target_out.readLine());
		} catch (NumberFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		interactions += 1;
		//System.out.println("Reply: "+r);
		return r;
	}
	
	private int interact(final BigInteger ciphertext) {
		String ciphertext_str = String.format("%0"+this.k*2+"X", ciphertext);
		return interact("", ciphertext_str);
	}

	/*This in abstract class*/
	@Override
	public String getRecoveredMaterial() {
		String s = "";
		for(byte b : this.recovered_bytes){
			s += String.format("%02X", b);
		}
		return s;
	}

	/*This is abstract class*/
	@Override
	public int getInteractions() {
		return interactions;
	}

	/*This is abstract in abstract class*/
	@Override
	public void attack() {
		//int r = interact(ciphertext);
		//System.out.println(r);
		BigInteger f1_over_2 = step1();
		BigInteger f2		 = step2(f1_over_2);
		BigInteger plaintext = step3(f2);
		System.out.println(String.format("OAEP encoded message: %0"+this.k*2+"X", plaintext));
		
		byte[] EM = I2OSP(plaintext, this.k);
		this.recovered_bytes = OAEPDecode(EM);
	}
	
	/**
	 * 
	 * @return f1/2 from step 1 of the attack
	 */
	private BigInteger step1() {
		int counter = 0;
		BigInteger multiplier = BigInteger.valueOf(2).modPow(e, N);
		BigInteger payload = ciphertext.multiply(multiplier).mod(N);
		while(interact(payload) != 1) {
			payload = payload.multiply(multiplier).mod(N);
			counter++;
		}
		return BigInteger.ZERO.setBit(counter);
	}
	
	/**
	 * 
	 * @param f1_over_2
	 * @return f2 from step 2 of the attack
	 */
	private BigInteger step2(BigInteger f1_over_2) {
		BigInteger f2 = N.add(B).divide(B).multiply(f1_over_2);
		BigInteger payload = f2.modPow(e, N).multiply(ciphertext).mod(N);
		
		while(interact(payload) == 1) {
			f2 = f2.add(f1_over_2);
			payload = f2.modPow(e, N).multiply(ciphertext).mod(N);
		}
		return f2;
	}
	
	/**
	 * 
	 * @param f2
	 * @return
	 */
	private BigInteger step3(BigInteger f2) {
		BigInteger TWO = BigInteger.valueOf(2);
		BigInteger m_min = ceilDivide(N, f2);
		BigInteger m_max = N.add(B).divide(f2);
		while(m_min.compareTo(m_max) != 0){
			BigInteger ftmp = TWO.multiply(B).divide(m_max.subtract(m_min));
			BigInteger i = ftmp.multiply(m_min).divide(N);
			BigInteger f3 = ceilDivide(i.multiply(N), m_min);
			int r = interact(f3.modPow(e, N).multiply(ciphertext).mod(N));
			if(r == 1) {
				m_min = ceilDivide(i.multiply(N).add(B), f3);
			}
			else {
				m_max = i.multiply(N).add(B).divide(f3);
			}
			System.out.println(f3);
		}
		if(m_min.modPow(e, N).compareTo(ciphertext) != 0) {
			System.err.println("Incorrect plaintext recovered..Terminating!");
			System.exit(-1);
		}
		
		return m_min;
	}
	
	private byte[] OAEPDecode(byte[] EM) {
		
		
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		// 3.a
		if(this.label != null){
			md.update(this.label);
		}
		byte[] lHash = md.digest();
		int hLen = lHash.length;
		
		System.out.print("Label hash(lHash): ");
		for(byte b:lHash) {
			System.out.print(String.format("%02X",b));
		}
		System.out.println();
		
		// 3.b
		byte Y = EM[0];
		byte[] maskedSeed = Arrays.copyOfRange(EM, 1, 1+hLen);
		byte[] maskedDB   = Arrays.copyOfRange(EM, 1+hLen, this.k);
		
		// 3.c
		byte[] seedMask = MGF1(maskedDB, hLen);
		
		// 3.d
		byte[] seed = new byte[hLen];
		for(int i = 0;i<hLen;i++){
			seed[i] = (byte) (maskedSeed[i] ^ seedMask[i]);
		}
		
		// 3.e
		byte[] dbMask = MGF1(seed, this.k - hLen - 1);
		
		// 3.f
		byte[] DB = new byte[this.k - hLen - 1];
		System.out.print("Padded message(DB): ");
		for(int i = 0; i<this.k - hLen - 1; i++) {
			DB[i] = (byte) (maskedDB[i] ^ dbMask[i]);
			System.out.print(String.format("%02X", DB[i]));
		}
		System.out.println();
		
		// 3.g
		if(Y != 0) {
			System.err.println("Y is nonzero!");
			System.exit(-1);
		}
		byte[] lHash2 = Arrays.copyOfRange(DB, 0, hLen);
		if(!Arrays.equals(lHash, lHash2)) {
			System.err.println("Hash not equal!");
			System.exit(-1);
		}
		int msg_start = hLen - 1;
		do {
			msg_start++;
			if(DB[msg_start] != 0x00 && DB[msg_start] != 0x01) {
				System.err.println("Malformed DB");
				System.exit(-1);
			}
		} while(DB[msg_start] != 0x01);
		msg_start++;
		
		return Arrays.copyOfRange(DB, msg_start, this.k - hLen - 1);
		
	}
	
	private static BigInteger ceilDivide(final BigInteger a, final BigInteger b) {
		return a.add(b.subtract(BigInteger.ONE)).divide(b);
	}
	
	private static byte[] I2OSP(BigInteger x, int xLen) {
		byte[] bytes = x.toByteArray();
		byte[] result = new byte[xLen];
		System.arraycopy(bytes, 0, result, xLen-bytes.length, bytes.length);
		return result;
	}
	
	private static byte[] I2OSP(int x, int xLen) {
		return I2OSP(BigInteger.valueOf(x), xLen);
	}
	
	private static byte[] MGF1(byte[] mgfSeed, int maskLen) {
		ArrayList<Byte> res = new ArrayList<Byte>(maskLen);
		byte[] final_res = new byte[maskLen];
		
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		int hLen = md.getDigestLength();
		for(int i = 0; i<(maskLen+hLen-1) / hLen;i++) {
			byte[] C = I2OSP(i, 4);
			md.reset();
			md.update(mgfSeed);
			md.update(C);
			byte[] hash = md.digest();
			for(int k=0;k<hLen;k++) {
				res.add(hash[k]);
			}
		}
		for(int i = 0; i<maskLen; i++){
			final_res[i] = res.get(i);
		}
		return final_res;
	}

}
