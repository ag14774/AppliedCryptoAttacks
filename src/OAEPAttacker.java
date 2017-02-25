import java.io.*;
import java.math.BigInteger;

public class OAEPAttacker implements IAttacker {
	
	/* Move these to AbstractAttacker */
	private BufferedReader target_out = null;
	private PrintWriter target_in = null;
	private int interactions;
	
	private BigInteger N;
	private BigInteger e;
	private BigInteger label;
	private BigInteger ciphertext;
	
	private int k; //How many bytes
	private BigInteger B;
	
	
	
	public OAEPAttacker(BufferedReader target_out, PrintWriter target_in,
						String N_hex, String e_hex, String label_hex,
						String ciphertext_hex) {
		/*First 3 lines to abstract class*/
		this.target_out = target_out;
		this.target_in = target_in;
		this.interactions = 0;
		
		this.N = new BigInteger(N_hex, 16);
		this.e = new BigInteger(e_hex, 16);
		this.label = new BigInteger(label_hex, 16);
		this.ciphertext = new BigInteger(ciphertext_hex, 16);
		this.k = N_hex.length() / 2;  // Number of bytes
		this.B = new BigInteger("0").setBit(8*(k-1));
		
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
		System.out.println("Reply: "+r);
		return r;
	}
	
	private int interact(final BigInteger label, final BigInteger ciphertext) {
		String label_str = String.format("%X", label);
		String ciphertext_str = String.format("%0"+this.k*2+"X", ciphertext);
		return interact(label_str, ciphertext_str);
	}
	
	private int interact(final BigInteger ciphertext) {
		String ciphertext_str = String.format("%0"+this.k*2+"X", ciphertext);
		return interact("", ciphertext_str);
	}

	/*This in abstract class*/
	@Override
	public String getRecoveredMaterial() {
		// TODO Auto-generated method stub
		return null;
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
		System.out.println(String.format("Plaintext: %0"+this.k*2+"X", plaintext));

	}
	
	/**
	 * 
	 * @return f1/2 from step 1 of the attack
	 */
	private BigInteger step1() {
		int counter = 0;
		BigInteger multiplier = new BigInteger("2").modPow(e, N);
		BigInteger payload = ciphertext.multiply(multiplier);
		payload = payload.mod(N);
		while(interact(payload) != 1) {
			payload = payload.multiply(multiplier);
			payload = payload.mod(N);
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
		return null;
	}
	
	/**
	 * 
	 * @param f2
	 * @return
	 */
	private BigInteger step3(BigInteger f2) {
		return null;
	}

}
