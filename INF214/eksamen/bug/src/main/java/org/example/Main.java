package org.example;

public class Main {
	public static void main(String[] args) throws Exception {
		if (args.length == 0) {
			System.out.println("Usage: java VulnerableEcho <message>");
			return;
		}

		// ❌ Vulnerable: user input is concatenated into a shell command
		String command = "echo " + args[0];

		Process process = Runtime.getRuntime().exec(
				new String[] { "sh", "-c", command }
		);

		process.waitFor();
	}}