import java.io.*;

public class Launcher {

	private Process target = null;

	private BufferedReader target_out = null;
	private PrintWriter target_in = null;

	IAttacker attacker = null;

	public Launcher(String device) throws IOException {
		this.target = Runtime.getRuntime().exec(device);

		this.target_out = new BufferedReader(new InputStreamReader(target.getInputStream()));
		this.target_in = new PrintWriter(target.getOutputStream(), true);
	}

	public void setupStage1(String conf) {
		String[] file = null;
		try (BufferedReader in = new BufferedReader(new FileReader(conf))){
			file = in.lines().toArray(size -> new String[size]);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		attacker = new OAEPAttacker(target_out, target_in, file[0], file[1], file[2], file[3]);
	}

	public void setupStage2(String conf) {
		String[] file = null;
		try (BufferedReader in = new BufferedReader(new FileReader(conf))){
			file = in.lines().toArray(size -> new String[size]);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		attacker = new TimeAttacker(target_out, target_in, file[0], file[1]);

	}

	public void setupStage3() {
		attacker = new FaultAttacker(target_out, target_in);
	}

	public void setupStage4() {
		attacker = new PowerAttacker(target_out, target_in);
	}
	
	public static void usage(){
		System.out.println("==USAGE==");
		System.out.println("java -cp . Launcher <stage[1234]> <path to ${USER}.D> <path to ${USER}.conf>");
	}

	public static void main(String[] args) {
		if (args.length < 2) {
			System.err.println("Wrong number of arguments!");
			System.exit(-1);
		}
		
		Launcher launcher = null;
		try {
			launcher = new Launcher(args[1]);
		} catch (IOException e) {
			e.printStackTrace();
		}

		switch (args[0]) {
		case "stage1":
			launcher.setupStage1(args[2]);
			break;
		case "stage2":
			launcher.setupStage2(args[2]);
			break;
		case "stage3":
			launcher.setupStage3();
			break;
		case "stage4":
			launcher.setupStage4();
			break;
		default:
			System.err.println("Illegal arguments!");
			System.exit(-1);
		}
		
		launcher.attacker.attack();
		
		System.out.println(launcher.attacker.getRecoveredMaterial());
		System.out.println(launcher.attacker.getInteractions());

	}

}
