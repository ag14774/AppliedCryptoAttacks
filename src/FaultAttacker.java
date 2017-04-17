import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class FaultAttacker extends AbstractAttacker {
	
	final private static int s_box[] = {
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	};
	
	final private static int s_inv[] = {
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
	};
	
	final private static int h_r[] = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
		0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
		0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
		0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
		0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
		0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
		0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
		0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
		0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
		0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
		0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
		0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
		0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
		0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
	};
	
	private int[] mul2;
	private int[] mul3;
	private int[] mul9;
	private int[] mul11;
	private int[] mul13;
	private int[] mul14;
	
	private int[] x;
	private int[] xprime;
	
	private byte[] msg;
	private byte[] enc;
	private Set<PartialKeyHypothesis> hypEqSet1;
	private Set<PartialKeyHypothesis> hypEqSet2;
	private Set<PartialKeyHypothesis> hypEqSet3;
	private Set<PartialKeyHypothesis> hypEqSet4;
	private Cipher AES;
	
	public FaultAttacker(BufferedReader target_out, PrintWriter target_in) {
		super(target_out, target_in);
		this.precompute_all_tables();
		this.msg = new byte[16];
		new Random().nextBytes(msg);
		this.x 		= interact( byteArrayToIntArray(msg), ""          );
	    this.xprime = interact( byteArrayToIntArray(msg), "8,1,0,0,0" );
	    
	    this.enc = intToByteArray(this.x);
	    
	    try {
			this.AES = Cipher.getInstance("AES/ECB/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}

	}
	
	private int gf28_mulx(byte a) {
		if( (a & 0x80 ) == 0x80 ) {
			return 0xFF & (0x1B ^ ( a << 1 ));
		}
		else {
			return 0xFF &         ( a << 1 );
		}
	}
	
	private int gf28_mul(byte a, byte b) {
		byte t = 0;
		for(int i = 7; i >= 0; i--) {
			t = (byte) gf28_mulx( t );
			if( ((b>>i) & 1) != 0) {
				t ^= a;
			}
		}
		return 0xFF & t;
	}
	
	private void precompute_all_tables() {
		this.mul2 = new int[256];
		this.mul3 = new int[256];
		this.mul9 = new int[256];
		this.mul11 = new int[256];
		this.mul13 = new int[256];
		this.mul14 = new int[256];
		for(int i = 0; i<256; i++) {
			this.mul2[i]  = gf28_mul((byte)i,(byte)2);
			this.mul3[i]  = this.mul2[i] ^ i;
			this.mul9[i]  = gf28_mul((byte)i,(byte)9);
			this.mul11[i] = gf28_mul((byte)i,(byte)11);
			this.mul13[i] = gf28_mul((byte)i,(byte)13);
			this.mul14[i] = gf28_mul((byte)i,(byte)14);
		}
	}
	
	public int[] interact(int[] m, String fault) {
		String message_hex = intArrayToHex(m);
		this.target_in.println(fault);
		this.target_in.println(message_hex);
		this.target_in.flush();
		this.interactions++;
		try {
			return hexToIntArray(this.target_out.readLine());
		} catch (IOException e) {
			e.printStackTrace();
		}
		return m;
	}

	private void filter_key_space(boolean intersect) {
		Set<PartialKeyHypothesis> hyp1 = this.hypEqSet1;
		Set<PartialKeyHypothesis> hyp2 = this.hypEqSet2;
		Set<PartialKeyHypothesis> hyp3 = this.hypEqSet3;
		Set<PartialKeyHypothesis> hyp4 = this.hypEqSet4;
		this.hypEqSet1 = new HashSet<PartialKeyHypothesis>();
		this.hypEqSet2 = new HashSet<PartialKeyHypothesis>();
		this.hypEqSet3 = new HashSet<PartialKeyHypothesis>();
		this.hypEqSet4 = new HashSet<PartialKeyHypothesis>();

		boolean[] valid = new boolean[4];
		boolean[] valid_restore_point1 = new boolean[4];
		boolean[] valid_restore_point2 = new boolean[4];
		for(int d = 0; d < 256; d++) {
			int d1 = d;
			int d2 = mul2[d];
			int d3 = mul3[d];
			boolean allInvalid = true;
			
			for(int k1 = 0; k1 < 256; k1++) { //1st equation of each set
				Arrays.fill(valid, false);
				allInvalid = true;
				if((s_inv[x[0] ^ k1] ^ s_inv[xprime[0] ^ k1]) == d2){
					allInvalid = false;
					valid[0] = true;
				}
				if((s_inv[x[4] ^ k1] ^ s_inv[xprime[4] ^ k1]) == d1){
					allInvalid = false;
					valid[1] = true;
				}
				if((s_inv[x[8] ^ k1] ^ s_inv[xprime[8] ^ k1]) == d1){
					allInvalid = false;
					valid[2] = true;
				}
				if((s_inv[x[12] ^ k1] ^ s_inv[xprime[12] ^ k1]) == d3){
					allInvalid = false;
					valid[3] = true;
				}
				if(allInvalid) continue;
				for(int k2 = 0; k2 < 256; k2++) { //2nd equation of each set
					System.arraycopy(valid, 0, valid_restore_point1, 0, 4);
					allInvalid = true;
					if(valid[0] && (s_inv[x[13] ^ k2] ^ s_inv[xprime[13] ^ k2]) == d1){
						allInvalid = false;
					}
					else {
						valid[0] = false;
					}
					if(valid[1] && (s_inv[x[1] ^ k2] ^ s_inv[xprime[1] ^ k2]) == d1){
						allInvalid = false;
					}
					else{
						valid[1] = false;
					}
					if(valid[2] && (s_inv[x[5] ^ k2] ^ s_inv[xprime[5] ^ k2]) == d3){
						allInvalid = false;
					}
					else{
						valid[2] = false;
					}
					if(valid[3] && (s_inv[x[9] ^ k2] ^ s_inv[xprime[9] ^ k2]) == d2){
						allInvalid = false;
					}
					else {
						valid[3] = false;
					}
					if(allInvalid) {
						System.arraycopy(valid_restore_point1, 0, valid, 0, 4);
						continue;
					}
					for(int k3 = 0; k3 < 256; k3++) { //3rd equation
						System.arraycopy(valid, 0, valid_restore_point2, 0, 4);
						allInvalid = true;
						if(valid[0] && (s_inv[x[10] ^ k3] ^ s_inv[xprime[10] ^ k3]) == d1){
							allInvalid = false;
						}
						else {
							valid[0] = false;
						}
						if(valid[1] && (s_inv[x[14] ^ k3] ^ s_inv[xprime[14] ^ k3]) == d3){
							allInvalid = false;
						}
						else {
							valid[1] = false;
						}
						if(valid[2] && (s_inv[x[2] ^ k3] ^ s_inv[xprime[2] ^ k3]) == d2){
							allInvalid = false;
						}
						else {
							valid[2] = false;
						}
						if(valid[3] && (s_inv[x[6] ^ k3] ^ s_inv[xprime[6] ^ k3]) == d1){
							allInvalid = false;
						}
						else {
							valid[3] = false;
						}
						if(allInvalid) {
							System.arraycopy(valid_restore_point2, 0, valid, 0, 4);
							continue;
						}
						for(int k4 = 0; k4 < 256; k4++) { //4th equation
							PartialKeyHypothesis hyp = new PartialKeyHypothesis(k1,k2,k3,k4);
							if(valid[0] && (s_inv[x[7] ^ k4] ^ s_inv[xprime[7] ^ k4]) == d3){
								if(!intersect || hyp1.contains(hyp))
									hypEqSet1.add(hyp);
							}
							if(valid[1] && (s_inv[x[11] ^ k4] ^ s_inv[xprime[11] ^ k4]) == d2){
								if(!intersect || hyp2.contains(hyp))
									hypEqSet2.add(hyp);
							}
							if(valid[2] && (s_inv[x[15] ^ k4] ^ s_inv[xprime[15] ^ k4]) == d1){
								if(!intersect || hyp3.contains(hyp))
									hypEqSet3.add(hyp);
							}
							if(valid[3] && (s_inv[x[3] ^ k4] ^ s_inv[xprime[3] ^ k4]) == d1){
								if(!intersect || hyp4.contains(hyp))
									hypEqSet4.add(hyp);
							}
						}
						System.arraycopy(valid_restore_point2, 0, valid, 0, 4);
					}
					System.arraycopy(valid_restore_point1, 0, valid, 0, 4);
				}
			}
		}
	}
	
	private void testHypothesis(PartialKeyHypothesis h1, PartialKeyHypothesis h2,
								PartialKeyHypothesis h3, PartialKeyHypothesis h4) {
		CompleteKeyHypothesis hyp = new CompleteKeyHypothesis(h1,h2,h3,h4);
		if(hyp.isValid()) {
			int[] key = inverseXKeyRounds(hyp.k,10,0);
			try {
				byte[] key_bytes = intToByteArray(key);
				System.out.println(Thread.currentThread().getName() + " is testing key: " + intArrayToHex(key));
				AES.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key_bytes, "AES"));
				byte[] enc_test = AES.doFinal(this.msg);
				if(Arrays.equals(enc_test, enc)){
					System.out.println("Key recovered!");
					this.recovered_bytes = intToByteArray(key);
					return;
				}
			} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}
			
		}
	}
	
	Callable<Void> createCallable(int startIndex, int endIndex, PartialKeyHypothesis[] outer) {
		return () -> {
			for(int k = startIndex; k<endIndex; k++){
				PartialKeyHypothesis h1 = outer[k];
				for(PartialKeyHypothesis h2 : hypEqSet2){
					for(PartialKeyHypothesis h3 : hypEqSet3){
						for(PartialKeyHypothesis h4 : hypEqSet4){
							testHypothesis(h1, h2, h3, h4);
							if(this.recovered_bytes != null) return null;
						}
					}
				}
			}
			return null;
		};
	}
	
	@Override
	public void attack() {
		
		boolean singleFault = true;

		filter_key_space(false);
		
		System.out.print("Step 1: ");
		System.out.print((long)hypEqSet1.size()*hypEqSet2.size()*hypEqSet3.size()*hypEqSet4.size());
		System.out.println(" possible keys");
		
		if(!singleFault) {
			this.msg = new byte[16];
			new Random().nextBytes(msg);
			this.x 		= interact( byteArrayToIntArray(msg), ""          );
		    this.xprime = interact( byteArrayToIntArray(msg), "8,1,0,0,0" );
		    this.enc = intToByteArray(this.x);
		    
			filter_key_space(true);
			
			System.out.print("After second fault: ");
			System.out.print((long)hypEqSet1.size()*hypEqSet2.size()*hypEqSet3.size()*hypEqSet4.size());
			System.out.println(" possible keys");
		}
	    
		System.out.println("Brute-forcing key...Please wait..This might take a while..");
		int cores = Runtime.getRuntime().availableProcessors();
		System.out.println("Using " + cores + " core(s)..");
		ExecutorService executor = Executors.newFixedThreadPool(cores);
		PartialKeyHypothesis outer[] = new PartialKeyHypothesis[hypEqSet1.size()];
		outer = hypEqSet1.toArray(outer);
		int workPerCore = outer.length / cores;
		List<Callable<Void>> todo = new ArrayList<Callable<Void>>(cores);
		for(int i = 0; i<cores; i++){
			int startIndex = i*workPerCore;
			int endIndex = startIndex + workPerCore;
			if(i == cores - 1)
				endIndex = outer.length;
			todo.add(createCallable(startIndex, endIndex, outer));
		}

		try {
			executor.invokeAll(todo);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
		executor.shutdown();

	}
	
	public int[] inverseXKeyRounds(final int[] key, int currentRound, int targetRound) {
		int[] res = key.clone();
		int[] cur = new int[16];
		int[] temp;
		for(int i=currentRound; i>targetRound; i--){
			temp = res;
			res  = cur;
			cur  = temp;
			res[  0 ] = cur[  0 ] ^ s_box[ cur[ 13 ] ^ cur[  9 ] ] ^ h_r[ i ];
			res[  1 ] = cur[  1 ] ^ s_box[ cur[ 14 ] ^ cur[ 10 ] ];
			res[  2 ] = cur[  2 ] ^ s_box[ cur[ 15 ] ^ cur[ 11 ] ];
			res[  3 ] = cur[  3 ] ^ s_box[ cur[ 12 ] ^ cur[  8 ] ];
			res[  4 ] = cur[  4 ] ^ 	   cur[  0 ];
			res[  5 ] = cur[  5 ] ^        cur[  1 ];
			res[  6 ] = cur[  6 ] ^ 	   cur[  2 ];
			res[  7 ] = cur[  7 ] ^ 	   cur[  3 ];
			res[  8 ] = cur[  8 ] ^        cur[  4 ];
			res[  9 ] = cur[  9 ] ^        cur[  5 ];
			res[ 10 ] = cur[ 10 ] ^        cur[  6 ];
			res[ 11 ] = cur[ 11 ] ^        cur[  7 ];
			res[ 12 ] = cur[ 12 ] ^        cur[  8 ];
			res[ 13 ] = cur[ 13 ] ^        cur[  9 ];
			res[ 14 ] = cur[ 14 ] ^        cur[ 10 ];
			res[ 15 ] = cur[ 15 ] ^        cur[ 11 ];
		}
		return res;
	}

	class PartialKeyHypothesis {
		
		int k1;
		int k2;
		int k3;
		int k4;
		
		public PartialKeyHypothesis(int k1, int k2, int k3, int k4) {
			this.k1 = k1;
			this.k2 = k2;
			this.k3 = k3;
			this.k4 = k4;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getOuterType().hashCode();
			result = prime * result + k1;
			result = prime * result + k2;
			result = prime * result + k3;
			result = prime * result + k4;
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			PartialKeyHypothesis other = (PartialKeyHypothesis) obj;
			if (!getOuterType().equals(other.getOuterType()))
				return false;
			if (k1 != other.k1)
				return false;
			if (k2 != other.k2)
				return false;
			if (k3 != other.k3)
				return false;
			if (k4 != other.k4)
				return false;
			return true;
		}

		private FaultAttacker getOuterType() {
			return FaultAttacker.this;
		}
		
		
		
	}
	
	class CompleteKeyHypothesis {
		int[] k;
		
		public CompleteKeyHypothesis(PartialKeyHypothesis set1, PartialKeyHypothesis set2,
									 PartialKeyHypothesis set3, PartialKeyHypothesis set4) {
			this.k = new int[16];
			this.k[0]  = set1.k1;
			this.k[13] = set1.k2;
			this.k[10] = set1.k3;
			this.k[7]  = set1.k4;
			
			this.k[4]  = set2.k1;
			this.k[1]  = set2.k2;
			this.k[14] = set2.k3;
			this.k[11] = set2.k4;
			
			this.k[8]  = set3.k1;
			this.k[5]  = set3.k2;
			this.k[2]  = set3.k3;
			this.k[15] = set3.k4;
			
			this.k[12] = set4.k1;
			this.k[9]  = set4.k2;
			this.k[6]  = set4.k3;
			this.k[3]  = set4.k4;
		}
		
		public byte[] getBytes() {
			byte[] res = new byte[16];
			for(int i=0; i<16; i++) {
				res[i] = (byte) this.k[i];
			}
			return res;
		}
		
		public boolean isValid() {
			int f = s_inv[ mul9[s_inv[x[12] ^ k[12]] ^ (k[12] ^ k[8] )]   ^
			               mul14[s_inv[x[9] ^ k[9]] ^ (k[9] ^ k[13])]     ^
			               mul11[s_inv[x[6] ^ k[6] ] ^ (k[14] ^ k[10])]   ^
			               mul13[s_inv[x[3] ^ k[3] ] ^ (k[15] ^ k[11])] ] ^
					s_inv[ mul9[s_inv[xprime[12] ^ k[12]] ^ (k[12] ^ k[8] )] ^
			               mul14[s_inv[xprime[9] ^ k[9]] ^ (k[9] ^ k[13])]   ^
			               mul11[s_inv[xprime[6] ^ k[6] ] ^ (k[14] ^ k[10])] ^
			               mul13[s_inv[xprime[3] ^ k[3] ] ^ (k[15] ^ k[11])] ];
			
			if( f != (s_inv[mul13[ s_inv[x[ 8  ] ^ k[8 ] ] ^ (k[8 ] ^ k[4])]   ^
			                mul9 [ s_inv[x[ 5  ] ^ k[5 ] ] ^ (k[9 ] ^ k[5])]   ^
			                mul14[ s_inv[x[ 2  ] ^ k[2 ] ] ^ (k[10] ^ k[6])]   ^
			                mul11[ s_inv[x[ 15 ] ^ k[15] ] ^ (k[11] ^ k[7])] ] ^
					  s_inv[mul13[ s_inv[xprime[ 8  ] ^ k[8 ] ] ^ (k[8 ] ^ k[4])]   ^
			                mul9 [ s_inv[xprime[ 5  ] ^ k[5 ] ] ^ (k[9 ] ^ k[5])]   ^
			                mul14[ s_inv[xprime[ 2  ] ^ k[2 ] ] ^ (k[10] ^ k[6])]   ^
			                mul11[ s_inv[xprime[ 15 ] ^ k[15] ] ^ (k[11] ^ k[7])]]) ) {
				return false;
			}
			
			if( mul2[f] != (s_inv[mul14[ s_inv[x[ 0  ] ^ k[0 ] ] ^ (k[0] ^ s_box[k[13] ^ k[9 ]]     ^ h_r[10])] ^
		                          mul11[ s_inv[x[ 13 ] ^ k[13] ] ^ (k[1] ^ s_box[k[14] ^ k[10]])]   ^
		                          mul13[ s_inv[x[ 10 ] ^ k[10] ] ^ (k[2] ^ s_box[k[15] ^ k[11]])]   ^
		                          mul9 [ s_inv[x[ 7  ] ^ k[7 ] ] ^ (k[3] ^ s_box[k[12] ^ k[8 ]])] ] ^
							s_inv[mul14[ s_inv[xprime[ 0  ] ^ k[0 ] ] ^ (k[0] ^ s_box[k[13] ^ k[9 ]]   ^ h_r[10])] ^
		                          mul11[ s_inv[xprime[ 13 ] ^ k[13] ] ^ (k[1] ^ s_box[k[14] ^ k[10]])] ^
		                          mul13[ s_inv[xprime[ 10 ] ^ k[10] ] ^ (k[2] ^ s_box[k[15] ^ k[11]])] ^
		                          mul9 [ s_inv[xprime[ 7  ] ^ k[7 ] ] ^ (k[3] ^ s_box[k[12] ^ k[8 ]])] ]) ) {
				return false;
			}
			
			if( mul3[f] != (s_inv[mul11[ s_inv[x[ 4  ] ^ k[4 ] ] ^ (k[4] ^ k[0])]   ^
		                          mul13[ s_inv[x[ 1  ] ^ k[1 ] ] ^ (k[5] ^ k[1])]   ^
		                          mul9 [ s_inv[x[ 14 ] ^ k[14] ] ^ (k[6] ^ k[2])]   ^
		                          mul14[ s_inv[x[ 11 ] ^ k[11] ] ^ (k[7] ^ k[3])] ] ^
						    s_inv[mul11[ s_inv[xprime[ 4  ] ^ k[4 ] ] ^ (k[4] ^ k[0] )] ^
		                          mul13[ s_inv[xprime[ 1  ] ^ k[1 ] ] ^ (k[5] ^ k[1] )] ^
		                          mul9 [ s_inv[xprime[ 14 ] ^ k[14] ] ^ (k[6] ^ k[2] )] ^
		                          mul14[ s_inv[xprime[ 11 ] ^ k[11] ] ^ (k[7] ^ k[3] )] ]) ) {
				return false;
			}
			
			return true;
			
		}
		
		@Override
		public String toString() {
			StringBuilder res = new StringBuilder(32);
			for(int i=0;i<16;i++){
				res.append(String.format("%02X",k[i] ));
			}
			return res.toString();
		}
		
	}

}
