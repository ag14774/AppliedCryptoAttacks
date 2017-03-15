import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class TimeAttacker extends AbstractAttacker {

	private BigInteger N;
	//private BigInteger e;
	private int N_bitcnt;
	private MontgomeryModel model;
	
	public TimeAttacker(BufferedReader target_out, PrintWriter target_in,
						String N_hex, String e_hex) {
		super(target_out, target_in);
		
		this.N = new BigInteger(N_hex, 16);
		//this.e = new BigInteger(e_hex, 16);
		this.N_bitcnt = N_hex.length() * 4;
		model = new MontgomeryModel(this.N);
		//System.out.println("Testing model: " + model.test());
	}
	
	public void interact(IntBigInt out, final BigInteger ciphertext) {
		String ciphertext_str = String.format("%X", ciphertext);
		this.target_in.println(ciphertext_str);
		this.target_in.flush();
		
		try {
			out.num = Integer.parseInt(this.target_out.readLine());
			out.bi = new BigInteger(this.target_out.readLine(), 16);
		} catch (NumberFormatException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		this.interactions += 1;
	}
	
	/* returns mean */
	public double generateCiphertexts(BigInteger[] mont_orig, BigInteger[] mont_curr, BigInteger[] msgs, int[] times, BigInteger d, int num) {
		IntBigInt res = new IntBigInt();
		BigInteger msg = null;
		BigInteger c = null;
		int time = 0;
		double sum = 0.0;
		for(int i=0; i<num; i++) {
			c = model.generateRandomUnsigned();
			BigInteger c_m = model.convertToMontgomery(c);
			//In case we need to regenerate ciphertexts
			//in the middle of the attack, we can use this
			//to generate the new ciphertexts and raise them
			//to our current candidate key
			BigInteger c_d = c.modPow(d, this.N);
			BigInteger c_dm = model.convertToMontgomery(c_d);
			interact(res, c);
			msg = res.bi;
			time = res.num;
			
			sum += time;
			mont_orig[i] = c_m;
			mont_curr[i] = c_dm;
			times[i] = time;
			msgs[i] = msg;
		}
		return sum/num;
	}

	private void modifyBit(StringBuilder key, int i, int bit){
		key.setLength(i+1);
		key.setCharAt(i, Character.forDigit(bit, 2));
	}
	
	@Override
	public void attack() {
		int num = 2500; //<--TRY THIS WITH 500(it will be increased to 1000 in the first step of the loop)
		BigInteger mont_orig[]  = null;
		BigInteger mont_curr[]  = null;
		BigInteger msgs[]	    = null;
		BigInteger mont_curr1[] = null;
		int[] times = null;
		//First bit is always 1 so start with the ciphertext raised to 2
		//This is equivalent with stopping just after the square operation
		//of the second iteration(for k2).
		double mean = 0;
		double std = 0;
		Stack<BigInteger[]> history = null;
		Stack<BigInteger> ctx_history = null;;
		StringBuilder s = null;
		BigInteger msg = BigInteger.ONE;
		BigInteger ctx = BigInteger.ZERO;
		int i = 0;
		int consecutive_errors = 0;
		int total_errors = 0;
		
		while(ctx.compareTo(msg) != 0) {
			if(i == 0 || i > this.N_bitcnt){
				num += 500;
				System.out.println("Setting sample size to " + num);
				mont_orig  = new BigInteger[num];
				mont_curr  = new BigInteger[num];
				msgs 	   = new BigInteger[num];
				mont_curr1 = new BigInteger[num];
				times = new int[num];
				//First bit is always 1 so start with the ciphertext raised to 2
				//This is equivalent with stopping just after the square operation
				//of the second iteration(for k2).
				mean = generateCiphertexts(mont_orig, mont_curr, msgs, times, BigInteger.valueOf(0b10), num);

				std = 0;
				for(long t : times) {
					std += (t-mean) * (t-mean);
				}
				std = Math.sqrt(std/(num-1));
				
				history = new Stack<BigInteger[]>();
				ctx_history = new Stack<BigInteger>();
				s = new StringBuilder();
				s.ensureCapacity(this.N_bitcnt);
				s.append('1');
				msg = model.convertToMontgomery(msgs[0]);
				ctx = mont_orig[0];
				i = 1;
				consecutive_errors = 0;
				total_errors = 0;
			}
			//System.out.println("\n"+s);
			history.push(mont_curr.clone()); //BigInteger is immutable so this is fast/not very slow
			ctx_history.push(ctx);
			System.out.print("Attacking bit "+i+"... ");
			int bit = attackNextBit(mont_curr, mont_curr1, mont_orig, std, times);
			ctx = model.montMul(ctx, ctx);
			if(bit == 1){
				ctx = model.montMul(ctx, mont_orig[0]);
				BigInteger[] temp = mont_curr;
				mont_curr = mont_curr1;
				mont_curr1 = temp;
				modifyBit(s, i, 1);
				System.out.println(bit);
				i++;
				consecutive_errors = 0;
			}
			else if(bit == 0){
				modifyBit(s, i, 0);
				System.out.println(bit);
				i++;
				consecutive_errors = 0;
			}
			else {
				if(consecutive_errors == 0) {
					// Better to guess 1 instead of 0.
					// It is a more 'risky' choice and
					// therefore if the choice is wrong
					// it will be detected sooner.
					System.out.println("not sure..trying with 1");
					ctx = model.montMul(ctx, mont_orig[0]);
					BigInteger[] temp = mont_curr;
					mont_curr = mont_curr1;
					mont_curr1 = temp;
					modifyBit(s, i, 1);
					consecutive_errors++;
					total_errors++;
					i++;
				}
				else { //error correction
					i = i - consecutive_errors;
					if(i == 0) continue;
					if(total_errors > 100) { //change this number so it is dependent on the number of bits of N instead of constant
						System.out.println("Too many errors! Result is unreliable..Trying again...");
						i = 0;
						continue;
					}
					System.out.println("backtracking to bit " + i + "...");
					int newbit = 1 - (s.charAt(i) - '0'); //flip
					System.out.println("Attacking bit "+i+"... flipping bit..trying with " + newbit);
					for(int j = 0; j<consecutive_errors; j++){
						history.pop();
						ctx_history.pop();
					}
					mont_curr = history.peek();
					ctx = ctx_history.peek();
					
					ctx = model.montMul(ctx, ctx);
					if(newbit == 1) {
						ctx = model.montMul(ctx, mont_orig[0]);
						for(int x=0;x<times.length;x++) {
							mont_curr[x] = model.montMul(mont_curr[x], mont_orig[x]);
							mont_curr[x] = model.montMul(mont_curr[x], mont_curr[x]);
						}
					}
					else {
						for(int x=0;x<times.length;x++) {
							mont_curr[x] = model.montMul(mont_curr[x], mont_curr[x]);
						}
					}
					modifyBit(s, i, newbit);
					consecutive_errors = 2;
					total_errors++;
					i++;
				}
			}
		}
		System.out.println(s);
		this.recovered_bytes = new BigInteger(s.toString(),2).toByteArray();
		this.recovered_bytes = Arrays.copyOfRange(this.recovered_bytes, 1, this.recovered_bytes.length);
	}
	
	/**
	 * If bit == 0, the result is returned to mont0_c, otherwise it is returned to mont1_c.
	 * When called, mont1_c should be a new array
	 **/
	private int attackNextBit(BigInteger[] mont0_c, BigInteger[] mont1_c, BigInteger[] mont_orig,
							  double times_std, final int[] times) {
		//from the t table(Critical values of the t distribution)
		//One-tail test 0.1 https://www2.palomar.edu/users/rmorrissette/Lectures/Stats/ttests/TTable.jpg
		//Degrees of freedom n1+n2-2=times.length-2
		final double t_test_1= 1.282; 

		// x is red or nored
		// y is time
		
		//sx and sxx will be the same
		int	   C0_red_count  = 0;
		double C0_red_mean   = 0;
		double C0_nored_mean = 0;
		
		int	   C1_red_count  = 0;
		double C1_red_mean   = 0;
		double C1_nored_mean = 0;
		
		IntBigInt res = new IntBigInt();
		for(int j=0; j<times.length; j++) {
			BigInteger mont_curr = mont0_c[j];
			// H0: Bit is 0, H1: Bit is 1
			model.montMul2(res, mont_curr, mont_curr);
			mont0_c[j] = res.bi;
			if( res.num == 1 /*if reduced*/) {
				++C0_red_count;
				C0_red_mean += times[j];
			}
			else {
				C0_nored_mean += times[j];
			}
			// H0: Bit is 1, H0: Bit is 0
			mont1_c[j] = model.montMul(mont_curr, mont_orig[j]);
			model.montMul2(res, mont1_c[j], mont1_c[j]);
			mont1_c[j] = res.bi;
			if( res.num == 1 /*if reduced*/) {
				++C1_red_count;
				C1_red_mean += times[j];
			}
			else {
				C1_nored_mean += times[j];
			}
		}
		
		C0_red_mean = C0_red_count > 0 ? C0_red_mean / C0_red_count : 0;
		C0_nored_mean = C0_nored_mean / (times.length-C0_red_count);
		//Point-biserial correlation coefficient
		double point_biserial0 = (C0_red_mean-C0_nored_mean)/times_std;
		point_biserial0 *= Math.sqrt((C0_red_count*(times.length-C0_red_count))/(double)(times.length*(times.length-1)));
		double t0_value = point_biserial0*Math.sqrt((times.length-2)/(1-point_biserial0*point_biserial0));
		
		C1_red_mean = C1_red_count > 0 ? C1_red_mean / C1_red_count : 0;
		C1_nored_mean = C1_nored_mean / (times.length-C1_red_count);
		//Point-biserial correlation coefficient
		double point_biserial1 = (C1_red_mean-C1_nored_mean)/times_std;
		point_biserial1 *= Math.sqrt((C1_red_count*(times.length-C1_red_count))/(double)(times.length*(times.length-1)));
		double t1_value = point_biserial1*Math.sqrt((times.length-2)/(1-point_biserial1*point_biserial1));
		
		//System.out.print(t0_value + " " + t1_value);
		if(t0_value<t_test_1) {
			if(t1_value<t_test_1) {
				return -1; //Not sure
			}
			else {
				return 1; //Bit is 1
			}
		}
		else { //possible bit 0
			if(t0_value>t1_value){
				return 0; //Bit is 0
			}
			else {
				return 1; //Bit is 1
			}
		}

	}
	
	class MontgomeryModel{
		
		// this is just to avoid recreating this object(used by some methods)
		private IntBigInt _internal_result;
		private int w = 64;
		private BigInteger base = BigInteger.ONE.shiftLeft(w);
		private BigInteger N;
		private int l_N;
		private BigInteger omega;
		private BigInteger rho_sqr;
		/***************************************************** 
		 * This is supposed to be used as an oracle.		 *
		 * It's not as fast as a low level implementation of *
		 * montgomery with limb access.						 *
		 *****************************************************/
		public MontgomeryModel(BigInteger N){
			this._internal_result = new IntBigInt();
			this.w = 64;
			this.base = BigInteger.ONE.shiftLeft(w);
			this.N = N;
			this.l_N = (int) Math.ceil(N.bitLength() / (double)w);
			long N0 = this.N.longValue();
			long omega = 1;
			for(int i=0; i<w-1; i++) {
				omega = omega * omega * N0;
			}
			omega = ~(omega-1);
			this.omega = ulong2BI(omega);
			this.rho_sqr = BigInteger.ONE;
			for(int i=0; i < (2*l_N*w); i++) {
				this.rho_sqr = this.rho_sqr.add(this.rho_sqr);
				if(this.rho_sqr.compareTo(this.N) >= 0) {
					this.rho_sqr = this.rho_sqr.subtract(this.N);
				}
			}
		}
		
		private BigInteger ulong2BI(long l) {
			final BigInteger bi = BigInteger.valueOf(l);
			return l >= 0 ? bi : bi.add(this.base);
		}

		public BigInteger generateRandomUnsigned() {
			BigInteger rnd;
			int byteLength = (int) Math.ceil(N.bitLength() / 8.0f);
			byte bytes[] = new byte[byteLength];
			SecureRandom random = new SecureRandom();
			do {
				random.nextBytes(bytes);
				rnd = new BigInteger(1, bytes);
			} while(rnd.compareTo(N) >= 0);
			return rnd;
		}
		
		public void montMul2(IntBigInt result, BigInteger x, BigInteger y) {
			result.num = 0;
			BigInteger r = BigInteger.ZERO;
			BigInteger baseminone = this.base.subtract(BigInteger.ONE);
			long temp = 0;
			long omegaL = omega.longValue();
			long x_0L = x.longValue();
			for(int i=0; i < this.l_N; i++) {
				BigInteger y_i = y.shiftRight(i*w).and(baseminone);
				long y_iL = y_i.longValue();
				long r_0L = r.longValue();
				temp = (x_0L * y_iL + r_0L) * omegaL;
				BigInteger u_i = ulong2BI(temp);
				r = r.add(y_i.multiply(x)).add(u_i.multiply(N)).shiftRight(w);
			}
			if(r.compareTo(N) >= 0) {
				r = r.subtract(N);
				result.num = 1;
			}
			result.bi = r;
		}
		
		public BigInteger montMul(BigInteger x, BigInteger y){
			montMul2(this._internal_result, x, y);
			return this._internal_result.bi;
		}
		
		public boolean isReducedDuringNextMontMult(BigInteger x, BigInteger y) {
			montMul2(this._internal_result, x, y);
			return this._internal_result.num == 0 ? false : true;
		}
		
		public BigInteger convertToMontgomery(BigInteger c){
			return montMul(c, this.rho_sqr);
		}
		
		protected boolean test(){
			BigInteger R = new BigInteger("354364354354");
			BigInteger mont = convertToMontgomery(R);
			BigInteger back2R = montMul(mont, BigInteger.ONE);
			if(R.compareTo(back2R) == 0) return true;
			return false;
		}
		
	}
	
}

class IntBigInt{
	protected BigInteger bi;
	protected int num;
}

