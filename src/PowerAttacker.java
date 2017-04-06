import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class PowerAttacker extends AbstractAttacker {
	
	final private static int first_N_traces = 3000;
	final private static int last_N_traces = 3000;
	
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

	//[time,plaintext_index]
	private int[][] start_traces;
	private int[][] end_traces;
	private int[][] plaintexts;
	private int[][] input_tweaks;
	
	public PowerAttacker(BufferedReader target_out, PrintWriter target_in) {
		super(target_out, target_in);
	}
	
	public Object[] interact(int[] i) {
		String tweak = intArrayToHex(i);
		this.target_in.println("0");
		this.target_in.println(tweak);
		this.target_in.flush();
		this.interactions++;
		String trace_str = "";
		String msg_str = "";
		try {
			trace_str = target_out.readLine();
			msg_str = target_out.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		String[] trace_split = trace_str.split(",");
		int length = Integer.parseInt(trace_split[0]);
		
		int[] start_trace = new int[first_N_traces];
		int[] end_trace   = new int[last_N_traces];
		
		for(int k = 1; k<=first_N_traces; k++) {
			start_trace[k-1] = Integer.parseInt(trace_split[k]);
		}
		for(int k = length-last_N_traces; k<length; k++) {
			end_trace[k-length+last_N_traces] = Integer.parseInt(trace_split[k]);
		}
		
		//a bit ugly but I don't want to create a new class for this.
		return new Object[] {this.hexToIntArray(msg_str), start_trace, end_trace};
		
	}
	
	private void addTrace(int[] input, Object[] res, int index){
		int[] plaintext = (int[]) res[0];
		int[] start_trace = (int[]) res[1];
		int[] end_trace = (int[]) res[2];
		
		input_tweaks[index] = input;
		plaintexts[index] = plaintext;
		for(int i = 0; i<first_N_traces; i++) {
			start_traces[i][index] = start_trace[i];
		}
		for(int i = 0; i<last_N_traces; i++) {
			end_traces[i][index] = end_trace[i];
		}
		
	}
	
	private void generateTraces(int sample_size) {
		start_traces = new int[first_N_traces][sample_size];
		end_traces   = new int[last_N_traces][sample_size];
		plaintexts = new int[sample_size][];
		input_tweaks = new int[sample_size][];
		byte[] rand_arr = new byte[16];
		Random rand = new Random();
		for(int k = 0; k<sample_size; k++){
			rand.nextBytes(rand_arr);			
			//Unlikely this is going to be a valid tweak -> C=0 but we don't mind
			//(will only affect testing)
			int[] input = byteArrayToIntArray(rand_arr);
			Object[] res = interact(input);
			addTrace(input, res, k);
		}
	}
	
	private int[][] generatePowerHypothesis(int[][] AESInputs, int byte_index) {
		int[][] res = new int[256][AESInputs.length];
		for(int k = 0; k<256; k++){
			for(int i = 0; i<AESInputs.length; i++){
				res[k][i] = AESInputs[i][byte_index] ^ k;
				res[k][i] = s_box[res[k][i]];
				res[k][i] = Integer.bitCount(res[k][i]);
			}
		}
		return res;
	}
	
	private float correlation(int[] A, int[] B) {
		if(A.length != B.length) return 100f; //we only need this for equal sized arrays
		float meanA = 0f;
		float meanB = 0f;
		for(int i = 0; i<A.length; i++){
			meanA += A[i];
			meanB += B[i];
		}
		meanA /= (float)A.length;
		meanB /= (float)B.length;
		float numerator = 0;
		float denom1 = 0;
		float denom2 = 0;
		for(int i = 0; i<A.length; i++){
			numerator += (A[i] - meanA) * (B[i] - meanB);
			denom1 += (A[i] - meanA) * (A[i] - meanA);
			denom2 += (B[i] - meanB) * (B[i] - meanB);
		}
		return (float) ( numerator / Math.sqrt(denom1 * denom2) );
	}
	
	private float[][] createCorrMatrix(int[][] A, int[][] B){
		float[][] res = new float[A.length][B.length];
		for(int i = 0; i<A.length; i++){
			for(int j = 0; j<B.length; j++){
				res[i][j] = correlation(A[i], B[j]);
			}
		}
		return res;
	}
	
	private float maxInArray(float[] arr) {
		float maxValue = arr[0];
		for(float v : arr){
			if(v > maxValue) {
				maxValue = v;
			}
		}
		return maxValue;
	}
	
	private int attackByte(int[][] AESInputs, int[][] traces, int byte_index) {
		int[][] hyp = generatePowerHypothesis(AESInputs, byte_index);
		float[][] coeff = createCorrMatrix(hyp, traces);
		int bestKey = -1;
		float maxValue = Float.NEGATIVE_INFINITY;
		for(int i = 0; i < coeff.length; i++) {
			float value = maxInArray(coeff[i]);
			if(maxValue < value){
				maxValue = value;
				bestKey = i;
			}
		}
//		System.out.println(byte_index + ": " + maxValue + " - " + bestKey);
//		System.out.print(maxValue + " ");
		return bestKey;
	}
	
	private Cipher initAES(int opmode, byte[] key){
		Cipher AES = null;
	    try {
			AES = Cipher.getInstance("AES/ECB/NoPadding");
			AES.init(opmode, new SecretKeySpec(key, "AES"));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
	    return AES;
	}
	
	private byte[] doFinal(Cipher AES, byte[] input){
		byte[] out = null;
		try {
			out = AES.doFinal(input);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return out;
	}
	
	private int[][] prepareForKey1(byte[] key2) {
		int[][] output = new int[input_tweaks.length][16];
		Cipher AES = initAES(Cipher.ENCRYPT_MODE, key2);
		for(int i = 0; i<input_tweaks.length; i++) {
			int[] tweak = input_tweaks[i];
			int[] plaintext = plaintexts[i];
			byte[] enc_tweak = doFinal(AES, this.intToByteArray(tweak));
			for(int k = 0; k<16; k++) {
				output[i][k] = 0xFF & (enc_tweak[k] ^ plaintext[k]);
			}
		}
		return output;
	}
	
	private boolean key_test(byte[] key1, byte[] key2){
		byte[] input_tweak = this.intToByteArray(input_tweaks[0]);
		Cipher AESEnc = initAES(Cipher.ENCRYPT_MODE, key2);
		Cipher AESDec = initAES(Cipher.DECRYPT_MODE, key1);
		byte[] tweak_enc = doFinal(AESEnc, input_tweak);
		byte[] dec = doFinal(AESDec, tweak_enc);
		int[] res = new int[16];
		for(int i=0;i<16;i++){
			res[i] = 0xFF & (dec[i] ^ tweak_enc[i]);
		}
//		System.out.println(this.intArrayToHex(res));
//		System.out.println(this.intArrayToHex(plaintexts[0]));
		return Arrays.equals(res, plaintexts[0]);
	}

	private boolean attack(int samples) {
		byte[] key1 = new byte[16];
		byte[] key2 = new byte[16];
		
		System.out.println("Generating traces..Please wait...");
		generateTraces(samples);
		System.out.println("Attacking key 2...");
		for(int i = 0; i<16; i++){
			System.out.print("Attacking byte " + i + " of key 2...");
			key2[i] = (byte) attackByte(this.input_tweaks, this.start_traces, i);
			System.out.println(key2[i] & 0xFF);
		}
		
		System.out.println();
		int[][] AESDecOutput = prepareForKey1(key2);
		
		System.out.println("Attacking key 1...");
		for(int i = 0; i<16; i++){
			System.out.print("Attacking byte " + i + " of key 1...");
			key1[i] = (byte) attackByte(AESDecOutput, this.end_traces, i);
			System.out.println(key1[i] & 0xFF);
		}
		
		this.recovered_bytes = new byte[key1.length + key2.length];
		System.arraycopy(key1, 0, this.recovered_bytes, 0, 16);
		System.arraycopy(key2, 0, this.recovered_bytes, 16, 16);
		return key_test(key1,key2);
	}
	
	@Override
	public void attack() {
		int max_trials = 3;
		int samples = 200;
		for(int i = 0; i<max_trials; i++) {
			if(attack(samples)) break;
			System.out.println("==========================================================");
			System.out.println("Attack failed..Increasing sample size to " + samples +"...");
			samples += 100;
		}
	}

}
